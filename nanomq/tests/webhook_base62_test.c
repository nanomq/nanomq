#include "tests_api.h"
#include "nng/supplemental/http/http.h"
#include "nng/mqtt/mqtt_client.h"

// Global counter for successful webhook hits
static int cnt = 0;
static nng_mtx *cnt_mtx = NULL;

#define TEST_PAYLOAD "messagei+/"
#define EXPECTED_ENCODED "2a7oZkl5ty6sG7"

// --- Helper: HTTP Server Callback ---
static void
test_http_server_cb(nng_aio *aio)
{
    nng_http_req *req = nng_aio_get_input(aio, 0);
    nng_http_res *res;
    void *data;
    size_t sz;
    int rv;
    char *body = NULL;

    // 1. Prepare Response
    if ((rv = nng_http_res_alloc(&res)) != 0) {
        nng_aio_finish(aio, rv);
        return;
    }
    nng_http_res_set_status(res, NNG_HTTP_STATUS_OK);
    nng_aio_set_output(aio, 0, res);

    // 2. Extract Data 
    // (This works now because we enabled collect_body in main)
    nng_http_req_get_data(req, &data, &sz);
    
    if (sz > 0) {
        body = nng_alloc(sz + 1);
        memcpy(body, data, sz);
        body[sz] = '\0';
        
        // Debug: Print what we got
        // printf("Webhook Body: %s\n", body);

        cJSON *json = cJSON_Parse(body);
        if (json) {
            cJSON *action = cJSON_GetObjectItem(json, "action");
            cJSON *topic  = cJSON_GetObjectItem(json, "topic");
            
            // Check Action & Topic
            if (action && strcmp(action->valuestring, "message_publish") == 0 &&
                topic && strncmp(topic->valuestring, "$SYS", 4) != 0) {
                
                cJSON *payload = cJSON_GetObjectItem(json, "payload");
                if (payload && cJSON_IsString(payload)) {
                    // Check Encoding
                    if (strcmp(payload->valuestring, EXPECTED_ENCODED) == 0) {
                        nng_mtx_lock(cnt_mtx);
                        cnt++;
                        nng_mtx_unlock(cnt_mtx);
                    } else {
                        printf("\t[FAIL] Encoding Mismatch! Got: %s\n", payload->valuestring);
                    }
                }
            }
            cJSON_Delete(json);
        }
        nng_free(body, sz + 1);
    } else {
        printf("\t[WARN] HTTP Callback fired but body size is 0!\n");
    }

    nng_aio_finish(aio, 0);
}

// Thread wrapper
static void broker_thr_func(void *arg) {
    broker_start_with_conf(arg);
}

// Client recv wrapper (keeps context alive)
static void client_recv_cb(void *arg) {}

int
main()
{
	if (!test_env_allows_network_binds() ||
	    !test_env_allows_port_bind(test_env_test_port()) ||
	    !test_env_allows_port_bind(8888)) {
		fprintf(stderr, "skip: test environment disallows listening sockets\n");
		return 0;
	}
	if (!test_env_has_executable("mosquitto_pub")) {
		fprintf(stderr,
		    "skip: required MQTT clients not found in PATH\n");
		return 0;
	}

    int        rv;
    nng_socket sock;
    nng_ctx    ctx;
    uint16_t   port = 8888;
    char       url[64];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/hook", port);

    nng_mtx_alloc(&cnt_mtx);

    // --- 1. HTTP Server Setup ---
    nng_http_server *server;
    nng_http_handler *handler;
    nng_url *url_obj;

    if ((rv = nng_url_parse(&url_obj, url)) != 0) fatal("url parse", rv);
    if ((rv = nng_http_server_hold(&server, url_obj)) != 0) fatal("server hold", rv);
    if ((rv = nng_http_handler_alloc(&handler, "/hook", test_http_server_cb)) != 0) fatal("handler alloc", rv);
    
    // <--- CRITICAL FIX 1: Allow POST method --->
    if ((rv = nng_http_handler_set_method(handler, "POST")) != 0) fatal("set method", rv);

    // <--- CRITICAL FIX 2: Collect Body --->
    // Without this, the callback fires before body is read, resulting in sz=0
    if ((rv = nng_http_handler_collect_body(handler, true, 1024 * 64)) != 0) fatal("collect body", rv);

    if ((rv = nng_http_server_add_handler(server, handler)) != 0) fatal("add handler", rv);
    if ((rv = nng_http_server_start(server)) != 0) fatal("server start", rv);
    nng_url_free(url_obj);


    // --- 2. NanoMQ Config ---
    conf *conf = get_dflt_conf();
    
    conf->web_hook.enable = true;
    conf->web_hook.url = nng_strdup(url);
    conf->web_hook.pool_size = 16;
	conf->web_hook.encode_payload = base62; // Use Base62 encoding
    
    // Header
    conf_http_header *header = calloc(1, sizeof(conf_http_header));
    header->key              = nng_strdup("content-type");
    header->value = nng_strdup("application/json");
    cvector_push_back(conf->web_hook.headers, header);
    conf->web_hook.header_count = cvector_size(conf->web_hook.headers);

    // Rules
    conf_web_hook_rule *rule = calloc(1, sizeof(conf_web_hook_rule));
    // Use the enum you confirmed earlier
    rule->event    = MESSAGE_PUBLISH;
    rule->rule_num = 1;
    rule->action = nng_strdup("message_publish");
    cvector_push_back(conf->web_hook.rules, rule);
    conf->web_hook.rule_count = cvector_size(conf->web_hook.rules);

    // Start Broker
    nng_thread *nmq_thr;
    nng_thread_create(&nmq_thr, broker_thr_func, conf);
    nng_msleep(1000);

    char cmd_pub[192];
    snprintf(cmd_pub, sizeof(cmd_pub),
	"mosquitto_pub -h 127.0.0.1 -p %s -t topic1 -m messagei+/ -q 2",
	test_env_test_port_text());
    FILE *p_pub = NULL;
    p_pub       = popen(cmd_pub, "r");
    if (p_pub == NULL || pclose(p_pub) != 0) {
	return EXIT_FAILURE;
    }

    // // --- 3. Client Connection ---
    // if ((rv = nng_mqtt_client_open(&sock)) != 0) fatal("client open", rv);
    // if ((rv = nng_ctx_open(&ctx, sock)) != 0) fatal("ctx open", rv);

    // // Prime Recv
    // nng_aio *recv_aio;
    // nng_aio_alloc(&recv_aio, client_recv_cb, NULL);
    // nng_ctx_recv(ctx, recv_aio);

    // // Connect Msg
    // nng_msg *connmsg;
    // nng_mqtt_msg_alloc(&connmsg, 0);
    // nng_mqtt_msg_set_packet_type(connmsg, NNG_MQTT_CONNECT);
    // nng_mqtt_msg_set_connect_proto_version(connmsg, 4); 
    // nng_mqtt_msg_set_connect_keep_alive(connmsg, 60);
    // nng_mqtt_msg_set_connect_clean_session(connmsg, true);
    // nng_mqtt_msg_set_connect_client_id(connmsg, "test-client");

    // nng_dialer dialer;
    // if ((rv = nng_dialer_create(&dialer, sock, "mqtt-tcp://127.0.0.1:1883")) != 0) fatal("dialer", rv);
    // nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, connmsg); 
    // nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);
    
    // nng_msleep(1000); 


    // // --- 4. Publish ---
    // nng_msg *msg;
    // nng_mqtt_msg_alloc(&msg, 0);
    // nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_PUBLISH);
    // nng_mqtt_msg_set_publish_topic(msg, "topic1");
    // nng_mqtt_msg_set_publish_payload(msg, (uint8_t *)TEST_PAYLOAD, strlen(TEST_PAYLOAD));
    // nng_mqtt_msg_set_publish_qos(msg, 1);
    
    // printf("Sending message...\n");
    // nng_aio *aio; 
    // nng_aio_alloc(&aio, NULL, NULL);
    // nng_aio_set_msg(aio, msg); 
    // nng_ctx_send(ctx, aio);
    // nng_aio_wait(aio);
    
    // if ((rv = nng_aio_result(aio)) != 0) {
    //     printf("Send failed: %d\n", rv);
    // } else {
    //     printf("Message sent successfully.\n");
    // }
    // nng_aio_free(aio);


    // --- 5. Verify ---
    int i = 0;
    while (i < 20) {
        nng_mtx_lock(cnt_mtx);
        int current_cnt = cnt;
        nng_mtx_unlock(cnt_mtx);
        if (current_cnt >= 1) break;
        nng_msleep(100);
        i++;
    }

    nng_mtx_lock(cnt_mtx);
    printf("Final Webhook Count: %d\n", cnt);
    assert(cnt == 1); 
    nng_mtx_unlock(cnt_mtx);


    // --- 6. Cleanup ---
    // nng_aio_cancel(recv_aio);
    // nng_aio_free(recv_aio);
    // nng_ctx_close(ctx);
    // nng_close(sock);
	broker_stop_for_test();
	nng_thread_destroy(nmq_thr);
	nng_http_server_stop(server);
	nng_http_server_release(server);
	// Let the asynchronous HTTP listener teardown complete before the next
	// webhook test reuses port 8888.
	nng_msleep(1000);
	nng_mtx_free(cnt_mtx);
	// Test-mode worker callbacks retain this configuration until process exit.
	// The process owns these allocations after the broker listener is closed.

	return 0;
}
