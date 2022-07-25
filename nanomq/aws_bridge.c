#include "aws_bridge.h"
#include "broker.h"
#include "mqtt_api.h"

#if defined(SUPP_AWS_BRIDGE)

#include <assert.h>
/* POSIX includes. */
#include <unistd.h>
/* MQTT API headers. */
#include <aws/core_mqtt.h>
#include <aws/core_mqtt_state.h>
#include <aws/transport_interface.h>
/* OpenSSL sockets transport implementation. */
#include <aws/openssl_posix.h>
/*Include backoff algorithm header for retry logic.*/
#include <aws/backoff_algorithm.h>
/* Clock for timer. */
#include <aws/clock.h>

#include "bridge.h"
#include "nanomq.h"
#include "nng/nng.h"
#include "nng/protocol/reqrep0/req.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/util/platform.h"
#include "pub_handler.h"

#define fatal(msg, rv)                                    \
	{                                                 \
		printf("%s:%s\n", msg, nng_strerror(rv)); \
		exit(1);                                  \
	}

/**
 * @brief ALPN (Application-Layer Protocol Negotiation) protocol name for AWS
 * IoT MQTT.
 *
 * This will be used if the AWS_MQTT_PORT is configured as 443 for AWS IoT MQTT
 * broker. Please see more details about the ALPN protocol for AWS IoT MQTT
 * endpoint in the link below.
 * https://aws.amazon.com/blogs/iot/mqtt-with-tls-client-authentication-on-port-443-why-it-is-useful-and-how-it-works/
 *
 * @note OpenSSL requires that the protocol string passed to it for
 * configuration be encoded with the prefix of 8-bit length information of the
 * string. Thus, the 14 byte (0x0e) length information is prefixed to the
 * string.
 */
#define AWS_IOT_MQTT_ALPN "\x0ex-amzn-mqtt-ca"

/**
 * @brief Length of ALPN protocol name.
 */
#define AWS_IOT_MQTT_ALPN_LENGTH ((uint16_t)(sizeof(AWS_IOT_MQTT_ALPN) - 1))

/**
 * @brief The maximum number of retries for connecting to server.
 */
#define CONNECTION_RETRY_MAX_ATTEMPTS (5U)

/**
 * @brief The maximum back-off delay (in milliseconds) for retrying connection
 * to server.
 */
#define CONNECTION_RETRY_MAX_BACKOFF_DELAY_MS (5000U)

/**
 * @brief The base back-off delay (in milliseconds) to use for connection retry
 * attempts.
 */
#define CONNECTION_RETRY_BACKOFF_BASE_MS (500U)

/**
 * @brief Timeout for receiving CONNACK packet in milli seconds.
 */
#define CONNACK_RECV_TIMEOUT_MS (1000U)

/**
 * @brief Transport timeout in milliseconds for transport send and receive.
 */
#define TRANSPORT_SEND_RECV_TIMEOUT_MS (5000)

/**
 * @brief Size of the network buffer for MQTT packets.
 */
#define NETWORK_BUFFER_SIZE (1024U)

/**
 * @brief Timeout for MQTT_ProcessLoop function in milliseconds.
 */
#define MQTT_PROCESS_LOOP_TIMEOUT_MS (500U)

/**
 * @brief Delay between MQTT publishes in seconds.
 */
#define DELAY_BETWEEN_PUBLISHES_SECONDS (1U)

/**
 * @brief Delay in seconds between two iterations of subscribePublishLoop().
 */
#define MQTT_SUBPUB_LOOP_DELAY_SECONDS (5U)

/* Each compilation unit must define the NetworkContext struct. */
struct NetworkContext {
	OpensslParams_t * pParams;
	nng_socket        sock;
	conf_bridge_node *node;
};

static int
establish_mqtt_session(MQTTContext_t *pMqttContext, bool createCleanSession,
    bool *pSessionPresent, conf_bridge_node *node)
{
	int               returnStatus = EXIT_SUCCESS;
	MQTTStatus_t      mqttStatus;
	MQTTConnectInfo_t connectInfo = { 0 };

	assert(pMqttContext != NULL);
	assert(pSessionPresent != NULL);

	/* Establish MQTT session by sending a CONNECT packet. */

	/* If #createCleanSession is true, start with a clean session
	 * i.e. direct the MQTT broker to discard any previous session data.
	 * If #createCleanSession is false, directs the broker to attempt to
	 * reestablish a session which was already present. */
	connectInfo.cleanSession = createCleanSession;

	/* The client identifier is used to uniquely identify this MQTT client
	 * to the MQTT broker. In a production device the identifier can be
	 * something unique, such as a device serial number. */
	connectInfo.pClientIdentifier = node->clientid;
	connectInfo.clientIdentifierLength =
	    node->clientid ? strlen(node->clientid) : 0;

	/* The maximum time interval in seconds which is allowed to elapse
	 * between two Control Packets.
	 * It is the responsibility of the Client to ensure that the interval
	 * between Control Packets being sent does not exceed the this Keep
	 * Alive value. In the absence of sending any other Control Packets,
	 * the Client MUST send a PINGREQ Packet. */
	connectInfo.keepAliveSeconds = node->keepalive;

	// #endif /* ifdef CLIENT_USERNAME */
	connectInfo.pUserName = node->username;
	connectInfo.userNameLength =
	    node->username ? strlen(node->username) : 0;

	connectInfo.pPassword = node->password;
	connectInfo.passwordLength =
	    node->password ? strlen(node->password) : 0;

	/* Send MQTT CONNECT packet to broker. */
	mqttStatus = MQTT_Connect(pMqttContext, &connectInfo, NULL,
	    CONNACK_RECV_TIMEOUT_MS, pSessionPresent);

	if (mqttStatus != MQTTSuccess) {
		returnStatus = EXIT_FAILURE;
		LogError(("Connection with MQTT broker failed with status %s.",
		    MQTT_Status_strerror(mqttStatus)));
	} else {
		LogInfo(("MQTT connection successfully established with "
		         "broker.\n\n"));
	}

	return returnStatus;
}

/*-----------------------------------------------------------*/
static int
connect_retries(NetworkContext_t *pNetworkContext, MQTTContext_t *pMqttContext,
    bool *pBrokerSessionPresent, conf_bridge_node *node)
{
	int                       returnStatus     = EXIT_FAILURE;
	BackoffAlgorithmStatus_t  backoffAlgStatus = BackoffAlgorithmSuccess;
	OpensslStatus_t           opensslStatus    = OPENSSL_SUCCESS;
	BackoffAlgorithmContext_t reconnectParams;
	ServerInfo_t              serverInfo;
	OpensslCredentials_t      opensslCredentials;
	uint16_t                  nextRetryBackOff;
	bool                      createCleanSession;

	/* Initialize information to connect to the MQTT broker. */
	serverInfo.pHostName      = node->host;
	serverInfo.hostNameLength = strlen(node->host);
	serverInfo.port           = node->port;

	/* Initialize credentials for establishing TLS session. */
	memset(&opensslCredentials, 0, sizeof(OpensslCredentials_t));
	opensslCredentials.pRootCaPath = node->tls.cafile;

	/* If #CLIENT_USERNAME is defined, username/password is used for
	 * authenticating the client. */
	opensslCredentials.pClientCertPath = node->tls.certfile;
	opensslCredentials.pPrivateKeyPath = node->tls.keyfile;

	/* AWS IoT requires devices to send the Server Name Indication (SNI)
	 * extension to the Transport Layer Security (TLS) protocol and provide
	 * the complete endpoint address in the host_name field. Details about
	 * SNI for AWS IoT can be found in the link below.
	 * https://docs.aws.amazon.com/iot/latest/developerguide/transport-security.html
	 */
	opensslCredentials.sniHostName = node->host;

	if (node->port == 443) {
		opensslCredentials.pAlpnProtos   = AWS_IOT_MQTT_ALPN;
		opensslCredentials.alpnProtosLen = AWS_IOT_MQTT_ALPN_LENGTH;
	}

	/* Initialize reconnect attempts and interval */
	BackoffAlgorithm_InitializeParams(&reconnectParams,
	    CONNECTION_RETRY_BACKOFF_BASE_MS,
	    CONNECTION_RETRY_MAX_BACKOFF_DELAY_MS,
	    CONNECTION_RETRY_MAX_ATTEMPTS);

	/* Attempt to connect to MQTT broker. If connection fails, retry after
	 * a timeout. Timeout value will exponentially increase until maximum
	 * attempts are reached.
	 */
	do {
		/* Establish a TLS session with the MQTT broker. This example
		 * connects to the MQTT broker as specified in AWS_IOT_ENDPOINT
		 * and AWS_MQTT_PORT at the demo config header. */
		LogInfo(("Establishing a TLS session to %s:%d.", node->host,
		    node->port));
		opensslStatus = Openssl_Connect(pNetworkContext, &serverInfo,
		    &opensslCredentials, TRANSPORT_SEND_RECV_TIMEOUT_MS,
		    TRANSPORT_SEND_RECV_TIMEOUT_MS);

		if (opensslStatus == OPENSSL_SUCCESS) {
			/* A clean MQTT session needs to be created, if there
			 * is no session saved in this MQTT client. */

			/* Sends an MQTT Connect packet using the established
			 * TLS session, then waits for connection
			 * acknowledgment (CONNACK) packet. */
			returnStatus = establish_mqtt_session(pMqttContext,
			    node->clean_start, pBrokerSessionPresent, node);

			if (returnStatus == EXIT_FAILURE) {
				/* End TLS session, then close TCP connection.
				 */
				(void) Openssl_Disconnect(pNetworkContext);
			}
		}

		if (returnStatus == EXIT_FAILURE) {
			/* Generate a random number and get back-off value (in
			 * milliseconds) for the next connection retry. */
			backoffAlgStatus = BackoffAlgorithm_GetNextBackoff(
			    &reconnectParams, rand(), &nextRetryBackOff);

			if (backoffAlgStatus ==
			    BackoffAlgorithmRetriesExhausted) {
				LogError(("Connection to the broker failed, "
				          "all attempts exhausted."));
				returnStatus = EXIT_FAILURE;
			} else if (backoffAlgStatus ==
			    BackoffAlgorithmSuccess) {
				LogWarn(("Connection to the broker failed. "
				         "Retrying connection "
				         "after %hu ms backoff.",
				    (unsigned short) nextRetryBackOff));
				Clock_SleepMs(nextRetryBackOff);
			}
		}
	} while ((returnStatus == EXIT_FAILURE) &&
	    (backoffAlgStatus == BackoffAlgorithmSuccess));

	return returnStatus;
}

static void
handle_recv_publish(MQTTPublishInfo_t *pub_info, uint16_t packet_id,
    nng_socket sock, conf_bridge_node *node)
{
	int rv;
	assert(pub_info != NULL);

	nng_msg *pub_msg;
	nng_mqtt_msg_alloc(&pub_msg, 0);
	nng_mqtt_msg_set_packet_type(pub_msg, NNG_MQTT_PUBLISH);

	nng_mqtt_msg_set_publish_payload(
	    pub_msg, (uint8_t *) pub_info->pPayload, pub_info->payloadLength);

	nng_mqtt_msg_set_publish_qos(pub_msg, pub_info->qos);
	nng_mqtt_msg_set_publish_retain(pub_msg, pub_info->retain);
	nng_mqtt_msg_set_publish_topic(pub_msg, pub_info->pTopicName);

	nng_msg *msg = NULL;
	if ((rv = encode_common_mqtt_msg(
	              &msg, pub_msg, node->clientid, node->proto_ver) != 0) ||
	    (rv = nng_sendmsg(sock, msg, 0)) != 0) {
		nng_msg_free(msg);
		LogError(("Failed to send publish message to broker: %d", rv));
	}
}

/*-----------------------------------------------------------*/

static void
event_cb(MQTTContext_t *pMqttContext, MQTTPacketInfo_t *pPacketInfo,
    MQTTDeserializedInfo_t *pDeserializedInfo)
{
	uint16_t packetIdentifier;

	assert(pMqttContext != NULL);
	assert(pPacketInfo != NULL);
	assert(pDeserializedInfo != NULL);

	packetIdentifier = pDeserializedInfo->packetIdentifier;

	/* Handle incoming publish. The lower 4 bits of the publish packet
	 * type is used for the dup, QoS, and retain flags. Hence masking
	 * out the lower bits to check if the packet is publish. */
	if ((pPacketInfo->type & 0xF0U) == MQTT_PACKET_TYPE_PUBLISH) {
		assert(pDeserializedInfo->pPublishInfo != NULL);
		/* Handle incoming publish. */
		nng_socket sock =
		    pMqttContext->transportInterface.pNetworkContext->sock;
		conf_bridge_node *node =
		    pMqttContext->transportInterface.pNetworkContext->node;
		handle_recv_publish(pDeserializedInfo->pPublishInfo,
		    packetIdentifier, sock, node);
	} else {
		uint8_t *    pPayload = NULL;
		size_t       pSize    = 0;
		MQTTStatus_t mqttStatus;
		/* Handle other packets. */
		switch (pPacketInfo->type) {
		case MQTT_PACKET_TYPE_SUBACK:
			mqttStatus = MQTT_GetSubAckStatusCodes(
			    pPacketInfo, &pPayload, &pSize);
			if (mqttStatus != MQTTSubAckFailure) {
				LogInfo(
				    ("Subscribed to the topic successfully."));
			}
			break;

		case MQTT_PACKET_TYPE_UNSUBACK:
			LogInfo(("Unsubscribed from the topic"));
			/* Make sure ACK packet identifier matches with Request
			 * packet identifier. */
			break;

		case MQTT_PACKET_TYPE_PINGRESP:
			/* Nothing to be done from application as library
			 * handles PINGRESP. */
			LogWarn(("PINGRESP should not be handled by the "
			         "application "
			         "callback when using MQTT_ProcessLoop.\n\n"));
			break;

		case MQTT_PACKET_TYPE_PUBACK:
			LogInfo(("PUBACK received for packet id %u.\n\n",
			    packetIdentifier));
			/* Cleanup publish packet when a PUBACK is received. */
			break;

		/* Any other packet type is invalid. */
		default:
			LogError(("Unknown packet type received:(%02x).\n\n",
			    pPacketInfo->type));
		}
	}
}

/*-----------------------------------------------------------*/

static int
initialize_mqtt(MQTTContext_t *pMqttContext, NetworkContext_t *pNetworkContext, MQTTFixedBuffer_t *networkBuffer, TransportInterface_t *transport )
{
	int                returnStatus = EXIT_SUCCESS;
	MQTTStatus_t       mqttStatus;
	// MQTTFixedBuffer_t *networkBuffer =
	//     nng_zalloc(sizeof(MQTTFixedBuffer_t));
	// TransportInterface_t *transport =
	//     nng_zalloc(sizeof(TransportInterface_t));

	assert(pMqttContext != NULL);
	assert(pNetworkContext != NULL);

	/* Fill in TransportInterface send and receive function pointers.
	 * For this demo, TCP sockets are used to send and receive data
	 * from network. Network context is SSL context for OpenSSL.*/
	transport->pNetworkContext = pNetworkContext;
	transport->send            = Openssl_Send;
	transport->recv            = Openssl_Recv;

	/* Fill the values for network buffer. */
	networkBuffer->pBuffer = nng_zalloc(NETWORK_BUFFER_SIZE);
	networkBuffer->size    = NETWORK_BUFFER_SIZE;

	/* Initialize MQTT library. */
	mqttStatus = MQTT_Init(
	    pMqttContext, transport, Clock_GetTimeMs, event_cb, networkBuffer);

	if (mqttStatus != MQTTSuccess) {
		returnStatus = EXIT_FAILURE;
		LogError(("MQTT init failed: Status = %s.",
		    MQTT_Status_strerror(mqttStatus)));
	}

	return returnStatus;
}

static int
subscribe_to_topic(MQTTContext_t *mqtt_ctx, conf_bridge_node *node)
{
	int          returnStatus = EXIT_SUCCESS;
	MQTTStatus_t mqttStatus;

	assert(mqtt_ctx != NULL);
	MQTTSubscribeInfo_t *sub_list =
	    nng_zalloc(sizeof(MQTTSubscribeInfo_t) * node->sub_count);

	/* This example subscribes to only one topic and uses QOS1. */
	for (size_t i = 0; i < node->sub_count; i++) {
		sub_list[i].qos               = node->sub_list[i].qos;
		sub_list[i].pTopicFilter      = node->sub_list[i].topic;
		sub_list[i].topicFilterLength = node->sub_list[i].topic_len;
	}

	/* Generate packet identifier for the SUBSCRIBE packet. */
	uint16_t sub_packet_id = MQTT_GetPacketId(mqtt_ctx);

	/* Send SUBSCRIBE packet. */
	mqttStatus =
	    MQTT_Subscribe(mqtt_ctx, sub_list, node->sub_count, sub_packet_id);

	if (mqttStatus != MQTTSuccess) {
		LogError(("Failed to send SUBSCRIBE packet to broker with "
		          "error = %s.",
		    MQTT_Status_strerror(mqttStatus)));
		returnStatus = EXIT_FAILURE;
	} else {
		LogInfo(("SUBSCRIBE to broker successfully.\n"));

		mqttStatus =
		    MQTT_ProcessLoop(mqtt_ctx, MQTT_PROCESS_LOOP_TIMEOUT_MS);

		if (mqttStatus != MQTTSuccess) {
			returnStatus = EXIT_FAILURE;
			LogError(
			    ("MQTT_ProcessLoop returned with status = %s.",
			        MQTT_Status_strerror(mqttStatus)));
		}
	}

	nng_free(sub_list, sizeof(MQTTSubscribeInfo_t) * node->sub_count);

	return returnStatus;
}

void
mqtt_thread(void *arg)
{
	int        rv;
	nng_socket req_sock;

	if ((rv = nng_req0_open(&req_sock)) != 0) {
		fatal("nng_rep0_open", rv);
	}

	if ((rv = nng_dial(
	         req_sock, INPROC_SERVER_URL, NULL, NNG_FLAG_NONBLOCK)) != 0) {
		fatal("nng_dial " INPROC_SERVER_URL, rv);
	}

	conf_bridge_node *node       = (conf_bridge_node *) arg;
	int               mqttStatus = 0, returnStatus = 0;
	int               ret_status = EXIT_SUCCESS;
	MQTTContext_t *   mqtt_ctx   = nng_zalloc(sizeof(MQTTContext_t));
	NetworkContext_t *net_ctx    = nng_zalloc(sizeof(NetworkContext_t));
	OpensslParams_t * ssl_params = nng_zalloc(sizeof(OpensslParams_t));
	MQTTFixedBuffer_t *networkBuffer =
	    nng_zalloc(sizeof(MQTTFixedBuffer_t));
	TransportInterface_t *transport =
	    nng_zalloc(sizeof(TransportInterface_t));
	bool clientSessionPresent = false, brokerSessionPresent = false;
	net_ctx->pParams = ssl_params;
	net_ctx->sock    = req_sock;
	net_ctx->node    = node;

	/* Seed pseudo random number generator with milliseconds. */
	srand(Clock_GetTimeMs());
	/* Initialize MQTT library. Initialization of the MQTT library needs to
	 * be done only once in this demo. */
	ret_status =
	    initialize_mqtt(mqtt_ctx, net_ctx, networkBuffer, transport);

	node->sock = mqtt_ctx;

	while (true) {
		if (returnStatus == EXIT_SUCCESS) {
			returnStatus = connect_retries(
			    net_ctx, mqtt_ctx, &brokerSessionPresent, node);
			if (returnStatus == EXIT_SUCCESS) {
				returnStatus =
				    subscribe_to_topic(mqtt_ctx, node);
				while (returnStatus == EXIT_SUCCESS) {
					returnStatus =
					    MQTT_ProcessLoop(mqtt_ctx,
					        MQTT_PROCESS_LOOP_TIMEOUT_MS);
					nng_msleep(
					    MQTT_PROCESS_LOOP_TIMEOUT_MS);
				}
				nng_msleep(
				    MQTT_SUBPUB_LOOP_DELAY_SECONDS * 1000);
			}
		}
	}
}

static int
client_init(conf_bridge_node *node)
{
	nng_thread *thread;
	nng_thread_create(&thread, mqtt_thread, node);
}

MQTTPublishInfo_t
aws_bridge_publish_msg(const char *topic, uint8_t *payload, uint32_t len,
    bool dup, uint8_t qos, bool retain)
{
	MQTTPublishInfo_t pub_info = {
		.qos             = qos >= 2 ? 1 : qos, // AWS requires QoS  < 2
		.pTopicName      = topic,
		.topicNameLength = strlen(topic),
		.pPayload        = payload,
		.payloadLength   = len,
		.retain          = retain,
	};

	return pub_info;
}

void
aws_bridge_forward(nano_work *work)
{
	MQTTPublishInfo_t pub_info = aws_bridge_publish_msg(
	    work->pub_packet->var_header.publish.topic_name.body,
	    work->pub_packet->payload.data, work->pub_packet->payload.len,
	    work->pub_packet->fixed_header.dup,
	    work->pub_packet->fixed_header.qos,
	    work->pub_packet->fixed_header.retain);

	int rv;

	for (size_t t = 0; t < work->config->aws_bridge.count; t++) {
		conf_bridge_node *node = work->config->aws_bridge.nodes[t];
		if (node->enable) {
			for (size_t i = 0; i < node->forwards_count; i++) {
				if (topic_filter(node->forwards[i],
				        work->pub_packet->var_header.publish
				            .topic_name.body)) {
					MQTTContext_t *mqtt_ctx = node->sock;
					uint16_t       packet_id =
					    MQTT_GetPacketId(mqtt_ctx);
					rv = MQTT_Publish(
					    mqtt_ctx, &pub_info, packet_id);

					/* Calling MQTT_ProcessLoop to process
					 * incoming publish echo, since
					 * application subscribed to the same
					 * topic the broker will send publish
					 * message back to the application.
					 * This function also sends ping
					 * request to broker if
					 * MQTT_KEEP_ALIVE_INTERVAL_SECONDS has
					 * expired since the last MQTT packet
					 * sent and receive ping responses. */
					int mqttStatus =
					    MQTT_ProcessLoop(mqtt_ctx,
					        MQTT_PROCESS_LOOP_TIMEOUT_MS);

					/* For any error in #MQTT_ProcessLoop,
					 * exit the loop and disconnect from
					 * the broker. */
					if (mqttStatus != MQTTSuccess) {
						LogError(("MQTT_ProcessLoop "
						          "returned with "
						          "status = %s.",
						    MQTT_Status_strerror(
						        mqttStatus)));
						rv = EXIT_FAILURE;
						break;
					}

					LogInfo(("Delay before continuing to "
					         "next iteration.\n\n"));

					// /* Leave connection idle for some
					// time.
					//  */
					sleep(DELAY_BETWEEN_PUBLISHES_SECONDS);
				}
			}
		}
	}
}

int
aws_bridge_client(conf_bridge_node *node)
{
	int ret = EXIT_SUCCESS;
	ret     = client_init(node);
	return ret;
}

#endif
