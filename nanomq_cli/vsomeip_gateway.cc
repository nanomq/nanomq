#if defined(SUPP_VSOMEIP_GATEWAY)
#include "vsomeip_gateway.h"

#include "nng/mqtt/mqtt_client.h"
#include "nng/nng.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/util/options.h"
#include "nng/supplemental/util/platform.h"
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "web_server.h"

#ifndef VSOMEIP_ENABLE_SIGNAL_HANDLING
#include <csignal>
#endif
#include <chrono>
#include <condition_variable>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>
#include <vsomeip/internal/logger.hpp>
#include <vsomeip/vsomeip.hpp>

#define LOG_INF VSOMEIP_INFO
#define LOG_ERR VSOMEIP_ERROR

typedef enum { INIT, RECV, WAIT, SEND } work_state;
struct work {
	work_state state;
	nng_aio   *aio;
	nng_msg   *msg;
	nng_ctx    ctx;
};

enum options {
	OPT_HELP = 1,
	OPT_CONFFILE,
};

static nng_optspec cmd_opts[] = {
	{ .o_name = "help", .o_short = 'h', .o_val = OPT_HELP },
	{ .o_name = "conf", .o_val = OPT_CONFFILE, .o_arg = true },
	{ .o_name = NULL, .o_val = 0 },
};

static char help_info[] =
    "Usage: nanomq_cli vsomeip_gateway [--conf <path>]\n\n"
    "  --conf <path>  The path of a specified nanomq_vsomeip_gateway.conf "
    "file \n";

static vsomeip_gateway_conf *conf_g = NULL;
static int                   nwork  = 32;

static bool is_available = false;

int
client_publish(nng_socket sock, const char *topic, uint8_t *payload,
    uint32_t payload_len, uint8_t qos, bool verbose)
{
	LOG_INF << "Send publish: '" << payload << "' to '" << topic << "'";
	int rv;

	// create a PUBLISH message
	nng_msg *pubmsg;
	nng_mqtt_msg_alloc(&pubmsg, 0);
	nng_mqtt_msg_set_packet_type(pubmsg, NNG_MQTT_PUBLISH);
	nng_mqtt_msg_set_publish_dup(pubmsg, 0);
	nng_mqtt_msg_set_publish_qos(pubmsg, qos);
	nng_mqtt_msg_set_publish_retain(pubmsg, 0);
	nng_mqtt_msg_set_publish_payload(
	    pubmsg, (uint8_t *) payload, payload_len);
	nng_mqtt_msg_set_publish_topic(pubmsg, topic);

	if ((rv = nng_sendmsg(sock, pubmsg, NNG_FLAG_NONBLOCK)) != 0) {
		LOG_ERR << "nng_sendmsg " << rv;
	}

	return rv;
}

class vsomeip_client {
    public:
	// Get the vSomeIP runtime and
	// create a application via the runtime, we could pass the application
	// name here otherwise the name supplied via the
	// VSOMEIP_APPLICATION_NAME environment variable is used
	vsomeip_client()
	    : rtm_(vsomeip::runtime::get())
	    , app_(rtm_->create_application())
	{
	}

	bool init()
	{
		// init the application
		if (!app_->init()) {
			LOG_ERR << "Couldn't initialize application";
			return false;
		}

		// register a state handler to get called back after
		// registration at the runtime was successful
		app_->register_state_handler(
		    std::bind(&vsomeip_client::on_state_cbk, this,
		        std::placeholders::_1));

		// register a callback for responses from the service
		app_->register_message_handler(vsomeip::ANY_SERVICE,
		    conf_g->service_instance_id, vsomeip::ANY_METHOD,
		    std::bind(&vsomeip_client::on_message_cbk, this,
		        std::placeholders::_1));

		// register a callback which is called as soon as the service
		// is available
		app_->register_availability_handler(conf_g->service_id,
		    conf_g->service_instance_id,
		    std::bind(&vsomeip_client::on_availability_cbk, this,
		        std::placeholders::_1, std::placeholders::_2,
		        std::placeholders::_3));

        std::set<vsomeip::eventgroup_t> its_groups;
        its_groups.insert(conf_g->service_eventgroup_id);
        app_->request_event(
                conf_g->service_id,
                conf_g->service_instance_id,
                conf_g->service_event_id,
                its_groups,
                vsomeip::event_type_e::ET_FIELD);
        app_->subscribe(conf_g->service_id, conf_g->service_instance_id, conf_g->service_eventgroup_id);

		return true;
	}

	void start()
	{
		// start the application and wait for the on_event callback to
		// be called this method only returns when app_->stop() is
		// called
		app_->start();
	}

	void on_state_cbk(vsomeip::state_type_e _state)
	{
		if (_state == vsomeip::state_type_e::ST_REGISTERED) {
			// we are registered at the runtime now we can request
			// the service and wait for the on_availability
			// callback to be called
			app_->request_service(
			    conf_g->service_id, conf_g->service_instance_id);
		}
	}

	void on_availability_cbk(vsomeip::service_t _service,
	    vsomeip::instance_t _instance, bool _is_available)
	{
		// Check if the available service is the the hello world
		// service
		if (conf_g->service_id == _service &&
		    conf_g->service_instance_id == _instance &&
		    _is_available) {
			// The service is available then we send the request
			// Create a new request
			is_available = true;
		}
	}

	void send_message(const std::vector<vsomeip::byte_t> &pl_data)
	{
		std::shared_ptr<vsomeip::message> rq = rtm_->create_request();
		// Set the hello world service as target of the request
		rq->set_service(conf_g->service_id);
		rq->set_instance(conf_g->service_instance_id);
		rq->set_method(conf_g->service_method_id);

		// Create a payload which will be sent to the service
		std::shared_ptr<vsomeip::payload> pl = rtm_->create_payload();

		pl->set_data(pl_data);
		rq->set_payload(pl);
		// Send the request to the service. Response will be delivered
		// to the registered message handler
		std::string s(pl_data.begin(), pl_data.end());
		LOG_INF << "Send request: '" << s << "'";
		app_->send(rq);
	}

	void on_message_cbk(const std::shared_ptr<vsomeip::message> &_response)
	{
		if (conf_g->service_id == _response->get_service() &&
		    conf_g->service_instance_id == _response->get_instance() &&
		    vsomeip::return_code_e::E_OK ==
		        _response->get_return_code()) {
			std::shared_ptr<vsomeip::payload> pl;
			switch (_response->get_message_type()) {
			case vsomeip_v3::message_type_e::MT_RESPONSE:
			case vsomeip_v3::message_type_e::MT_NOTIFICATION:
				pl =  _response->get_payload();
				client_publish(*conf_g->sock, conf_g->pub_topic,
				    (uint8_t *) pl->get_data(), pl->get_length(), 0, false);
				break;
			default:
				LOG_ERR << "Unsupport Recv response type: '" << (int)_response->get_message_type() << "'";
				break;
			}
		}
	}

	void stop()
	{
		// unregister the state handler
		app_->unregister_state_handler();
		// unregister the message handler
		app_->unregister_message_handler(vsomeip::ANY_SERVICE,
		    conf_g->service_instance_id, vsomeip::ANY_METHOD);
		// alternatively unregister all registered handlers at once
		app_->clear_all_handler();
		// release the service
		app_->release_service(
		    conf_g->service_id, conf_g->service_instance_id);
		// shutdown the application
		app_->stop();
	}

    private:
	std::shared_ptr<vsomeip::runtime>     rtm_;
	std::shared_ptr<vsomeip::application> app_;
};

#ifndef VSOMEIP_ENABLE_SIGNAL_HANDLING
vsomeip_client *vc_ptr(nullptr);
void
handle_signal(int _signal)
{
	if (vc_ptr != nullptr && (_signal == SIGINT || _signal == SIGTERM))
		vc_ptr->stop();
}
#endif

void
disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	LOG_INF << __FUNCTION__ << ": disconnected!";
}

void
set_sub_topic(nng_mqtt_topic_qos topic_qos[], int qos, char **topic_que)
{
	// for (int i = 0; i < TOPIC_CNT; i++) {
	topic_qos[0].qos = qos;
	LOG_INF << "topic: " << topic_que[0];
	topic_qos[0].topic.buf    = (uint8_t *) topic_que[0];
	topic_qos[0].topic.length = strlen(topic_que[0]);
	// }
	return;
}

void
connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	LOG_INF << __FUNCTION__ << ": connected!";
	nng_socket sock = *(nng_socket *) arg;

	nng_mqtt_topic_qos topic_qos[1];

	// set_sub_topic(topic_qos, 0, &conf->sub_topic);
	LOG_INF << "topic: " << conf_g->sub_topic;
	topic_qos[0].qos          = 0;
	topic_qos[0].topic.buf    = (uint8_t *) conf_g->sub_topic;
	topic_qos[0].topic.length = strlen(conf_g->sub_topic);

	size_t topic_qos_count =
	    sizeof(topic_qos) / sizeof(nng_mqtt_topic_qos);

	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_SUBSCRIBE);
	nng_mqtt_msg_set_subscribe_topics(msg, topic_qos, topic_qos_count);

	// Send subscribe message
	int rv = 0;
	rv     = nng_sendmsg(sock, msg, NNG_FLAG_ALLOC);
	if (rv != 0) {
		LOG_ERR << "nng_sendmsg" << rv;
	}
}

int
check_recv(nng_msg *msg)
{

	// Get PUBLISH payload and topic from msg;
	uint32_t p_len;
	uint32_t t_len;

	uint8_t    *p = nng_mqtt_msg_get_publish_payload(msg, &p_len);
	const char *t = nng_mqtt_msg_get_publish_topic(msg, &t_len);

	std::string payload(p, p + p_len);
	std::string topic(t, t + t_len);
	LOG_INF << "Recv message: '" << payload << "' from '" << topic << "'";

	if (p_len > 0) {
		if (is_available) {
			vc_ptr->send_message(
			    std::vector<uint8_t>(p, p + p_len));
		} else {
			LOG_ERR << "Dropped message, due to service is "
			           "unavailable";
		}
	}
	nng_msg_free(msg);

	return 0;
}

void
vsomeip_gateway_sub_cb(void *arg)
{
	struct work *work = reinterpret_cast<struct work *>(arg);
	nng_msg     *msg;
	int          rv;

	switch (work->state) {
	case INIT:
		work->state = RECV;
		nng_ctx_recv(work->ctx, work->aio);
		break;
	case RECV:
		if ((rv = nng_aio_result(work->aio)) != 0) {
			// nng_msg_free(work->msg);
			LOG_ERR << "nng_send_aio" << rv;
		}
		msg = nng_aio_get_msg(work->aio);

		if (-1 == check_recv(msg)) {
			abort();
		}

		work->state = RECV;
		nng_ctx_recv(work->ctx, work->aio);
		break;
	default:
		LOG_ERR << "bad state!" << NNG_ESTATE ;
		break;
	}
}

struct work *
proxy_alloc_work(nng_socket sock)
{
	struct work *w;
	int          rv;

	if ((w = reinterpret_cast<struct work *>(nng_alloc(sizeof(*w)))) ==
	    NULL) {
		LOG_ERR << "nng_alloc" << NNG_ENOMEM;
	}
	if ((rv = nng_aio_alloc(&w->aio, vsomeip_gateway_sub_cb, w)) != 0) {
		LOG_ERR << "nng_aio_alloc" << rv;
	}
	if ((rv = nng_ctx_open(&w->ctx, sock)) != 0) {
		LOG_ERR << "nng_ctx_open" << rv;
	}
	w->state = INIT;
	return (w);
}

int
client(const char *url, nng_socket *sock_ret)
{
	nng_socket   sock;
	nng_dialer   dialer;
	int          rv;
	struct work *works[nwork];

	if ((rv = nng_mqtt_client_open(&sock)) != 0) {
		LOG_ERR << "nng_socket" << rv;
		return rv;
	}

	*sock_ret = sock;

	for (int i = 0; i < nwork; i++) {
		works[i] = proxy_alloc_work(sock);
	}

	// Mqtt connect message
	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_proto_version(msg, conf_g->proto_ver);
	nng_mqtt_msg_set_connect_keep_alive(msg, conf_g->keepalive);
	nng_mqtt_msg_set_connect_clean_session(msg, conf_g->clean_start);
	if (conf_g->username) {
		nng_mqtt_msg_set_connect_user_name(msg, conf_g->username);
	}

	if (conf_g->password) {
		nng_mqtt_msg_set_connect_password(msg, conf_g->password);
	}

	nng_mqtt_set_connect_cb(sock, connect_cb, sock_ret);
	nng_mqtt_set_disconnect_cb(sock, disconnect_cb, NULL);

	if ((rv = nng_dialer_create(&dialer, sock, url)) != 0) {
		LOG_ERR << "nng_dialer_create" << rv;
	}

	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, msg);
	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	for (int i = 0; i < nwork; i++) {
		vsomeip_gateway_sub_cb(works[i]);
	}

	return 0;
}

int
vsomeip_gateway(vsomeip_gateway_conf *conf)
{
	nng_socket sock;
	client(conf->mqtt_url, &sock);
	conf->sock = &sock;
	vsomeip_client vc;
#ifndef VSOMEIP_ENABLE_SIGNAL_HANDLING
	vc_ptr = &vc;
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
#endif
	if (vc.init()) {
		vc.start();
		return 0;
	} else {
		return 1;
	}
}

static void
vsomeip_gateway_conf_init(vsomeip_gateway_conf *conf)
{
	// Init mqtt option
	conf->mqtt_url  = NULL;
	conf->pub_topic = NULL;
	conf->sub_topic = NULL;
	conf->username  = NULL;
	conf->password  = NULL;
	conf->clientid  = NULL;
	conf->proto_ver = 4;
	conf->keepalive = 60;

	conf->service_id          = 0;
	conf->service_instance_id = 0;
	conf->service_method_id   = 0;
	conf->service_event_id   = 0;
	conf->service_eventgroup_id   = 0;
	conf->conf_path           = NULL;
	return;
}

static int
vsomeip_gateway_conf_check_and_set(vsomeip_gateway_conf *conf)
{
	if (!conf->service_id) {
		LOG_ERR << "Pls set service id";
	}

	if (!conf->service_instance_id) {
		LOG_ERR << "Pls set service instance id";
	}

	if (!conf->service_method_id) {
		LOG_ERR << "Pls set service method id";
	}

	if (!conf->service_event_id) {
		LOG_ERR << "Pls set service event id";
	}

	if (!conf->service_eventgroup_id) {
		LOG_ERR << "Pls set service event group id";
	}

	if (!conf->conf_path) {
		LOG_INF << "Use default conf.";
	} else {
		char vsomeip_config[128];
		snprintf(vsomeip_config, 128, "VSOMEIP_CONFIGURATION=%s",
		    conf->conf_path);
		putenv(vsomeip_config);
	}

	if (!conf->sub_topic || !conf->pub_topic) {
		LOG_ERR << "Pls set sub/pub topic before.";
		return -1;
	}

	if (conf->mqtt_url == NULL) {
		conf->mqtt_url ? conf->mqtt_url
		               : nng_strdup("mqtt-tcp://broker.emqx.io:1883");
		LOG_INF << "Set default mqtt-url: " <<  conf->mqtt_url;
	}

	nwork = conf->parallel;

	conf_g = conf;
	return 0;
}

int
vsomeip_gateway_parse_opts(int argc, char **argv, vsomeip_gateway_conf *config)
{
	int   idx = 1;
	char *arg;
	int   val;
	int   rv;

	while ((rv = nng_opts_parse(
	            argc - 1, argv + 1, cmd_opts, &val, &arg, &idx)) == 0) {
		switch (val) {
		case OPT_HELP:
			printf("%s", help_info);
			exit(0);
			break;
		case OPT_CONFFILE:
			config->path = nng_strdup(arg);
			break;
		default:
			break;
		}
	}

	switch (rv) {
	case NNG_EINVAL:
		LOG_ERR <<
		    "Option" << argv[idx] << "is invalid.\nTry 'nanomq_cli vsomeip_gateway "
		    "--help' for "
		    "more information.\n";
		break;
	case NNG_EAMBIGUOUS:
		LOG_ERR <<
		    "Option" << argv[idx] << "is ambiguous (specify in full).\nTry "
		    "'nanomq_cli "
		    "vsomeip_gateway --help' for more information.\n";
		break;
	case NNG_ENOARG:
		LOG_ERR <<
		    "Option" << argv[idx] << "requires argument.\nTry 'nanomq_cli "
		    "vsomeip_gateway "
		    "--help' "
		    "for more information.\n";
		break;
	default:
		break;
	}

	return rv == -1;
}

int
vsomeip_gateway_start(int argc, char **argv)
{
	vsomeip_gateway_conf *conf =
	    (vsomeip_gateway_conf *) nng_alloc(sizeof(vsomeip_gateway_conf));
	if (conf == NULL) {
		LOG_ERR << "Memory alloc error.";
		exit(EXIT_FAILURE);
	}

	vsomeip_gateway_conf_init(conf);
	vsomeip_gateway_parse_opts(argc, argv, conf);
	conf_vsomeip_gateway_parse_ver2(conf);
	if (conf->http_server.enable) {
		proxy_info *info = proxy_info_alloc(PROXY_NAME_SOMEIP, conf,
		    conf->path, &conf->http_server, argc, argv);
		start_rest_server(info);
	}
	if (-1 != vsomeip_gateway_conf_check_and_set(conf)) {
		vsomeip_gateway(conf);
	}
	return 0;
}

int
vsomeip_gateway_dflt(int argc, char **argv)
{
	printf("%s", help_info);
	return 0;
}

#endif
