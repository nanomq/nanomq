//
// Zephyr broker entry point for the ART-Pi (STM32H750XBH6) — "embedded
// minimal conf" bootstrap over Ethernet.
//
// Zephyr has no filesystem, so the broker is started with conf_init()
// defaults plus a few field overrides, then broker() is called directly.
// broker_start() (file parsing, daemonize) is deliberately bypassed.
//
// Startup contract with apps/broker.c::broker(conf *):
//   * conf->url non-NULL  → broker listens on it (nmq-tcp:// ...)
//   * conf->ipc_internal  → cmd server over IPC transport; this build has
//                           NNG_TRANSPORT_IPC=OFF, so it must be false
//   * log_init() must run first: in the normal flow it is called by
//     broker_start_with_conf() right before broker(); broker() itself never
//     touches the nanolib log module
//   * broker() never returns: it parks in for(;;) nng_msleep(3600000)
//
// Networking: the ART-Pi reaches the LAN through its on-board Ethernet PHY
// (RMII + LAN8720A) rather than Wi-Fi, so main() waits for the interface and
// for a DHCPv4 lease before starting the broker — the 0.0.0.0 listeners are
// only reachable once the link has an address.  Mirrors
// demo/nanomq_zephyr_esp32s3/src/main.c, whose Wi-Fi bring-up plays the same
// role.
//
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_event.h>
#include <zephyr/net/dhcpv4.h>

#if defined(CONFIG_WIFI)
#include <zephyr/net/wifi_mgmt.h>
#endif

#if defined(CONFIG_USB_DEVICE_NETWORK_ECM)
#include <zephyr/usb/usb_device.h>
#include <zephyr/net/dhcpv4_server.h>
#endif

#include <string.h>
#include <time.h>

#if defined(CONFIG_BROKER_SNTP)
#include <zephyr/net/sntp.h>   // sntp_simple() — clock seed
#include <zephyr/sys/clock.h>  // sys_clock_settime()
#endif

#include "nng/nng.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/nanolib/log.h"
#include "mqtt_api.h" // log_init(conf_log *)

// broker() lives in nanomq/nanomq/apps/broker.c and is not declared in
// broker.h (which only exports broker_start/broker_start_with_conf).
extern int broker(conf *nanomq_conf);

static K_SEM_DEFINE(dhcp_bound_sem, 0, 1);

static volatile bool broker_running;

#if defined(CONFIG_BROKER_STATUS_INTERVAL_S) && (CONFIG_BROKER_STATUS_INTERVAL_S > 0)
//
// Periodic status line — see CONFIG_BROKER_STATUS_INTERVAL_S.
//
// nanolib prints the broker banner and "NanoMQ Broker is started
// successfully!" once, while broker() starts.  Anything attached to the
// console later never sees them, and on this board the SDIO driver's error
// logging can fill the console (ADR 0003).  One line a minute keeps "is it
// up, and on which address?" answerable — and proves the application is alive
// when the console looks like nothing but driver errors.
//

struct ipv4_capture {
	char *buf;
	size_t len;
};

static void
capture_ipv4_cb(struct net_if *iface, struct net_if_addr *ifaddr, void *user_data)
{
	struct ipv4_capture *cap = user_data;

	if ((cap->buf[0] == '\0') && (ifaddr->address.family == AF_INET) &&
	    ((ifaddr->addr_type == NET_ADDR_MANUAL) ||
	     (ifaddr->addr_type == NET_ADDR_DHCP))) {
		(void) net_addr_ntop(AF_INET, &ifaddr->address.in_addr, cap->buf,
		    cap->len);
	}
	ARG_UNUSED(iface);
}

static void
broker_status_thread(void *a, void *b, void *c)
{
	for (;;) {
		char buf[NET_IPV4_ADDR_LEN] = { 0 };
		struct ipv4_capture cap = { .buf = buf, .len = sizeof(buf) };
		struct net_if *iface;

		k_sleep(K_SECONDS(CONFIG_BROKER_STATUS_INTERVAL_S));
		if (!broker_running) {
			continue;
		}

		iface = net_if_get_default();
		if (iface != NULL) {
			net_if_ipv4_addr_foreach(iface, capture_ipv4_cb, &cap);
		}

		printk("broker: status running — uptime %us, MQTT "
		    "tcp://0.0.0.0:1883, REST http://0.0.0.0:8081, "
		    "WS :8083/mqtt, ipv4 %s\n",
		    (unsigned int)(k_uptime_get() / 1000),
		    (buf[0] != '\0') ? buf : "(none yet)");
	}
	ARG_UNUSED(a); ARG_UNUSED(b); ARG_UNUSED(c);
}
K_THREAD_DEFINE(broker_status, 2048, broker_status_thread, NULL, NULL, NULL,
		14, 0, 0);
#endif /* CONFIG_BROKER_STATUS_INTERVAL_S > 0 */

static void
net_event_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
    struct net_if *iface)
{
	switch (mgmt_event) {
	case NET_EVENT_IPV4_DHCP_BOUND:
		printk("eth: IPv4 address assigned (DHCPv4)\n");
		k_sem_give(&dhcp_bound_sem);
		break;
	default:
		break;
	}
	ARG_UNUSED(cb);
	ARG_UNUSED(iface);
}

//
// Ethernet bring-up: wait for the link, then for a DHCPv4 lease.
//
// Zephyr's Ethernet L2 marks the interface up only once the PHY reports
// carrier, so net_if_is_up() is the link indicator here: starting the DHCP
// client before carrier arrives fails with -ENETDOWN and the client is never
// retried.  The wait is bounded and noisy on purpose — a board with no cable,
// a PHY still held in reset or the wrong MDIO address all end up here, and
// the log has to say which stage stalled.
//
// CONFIG_NET_CONFIG_SETTINGS is deliberately not enabled: that module's
// AUTO_INIT defaults to y and would run a SYS_INIT hook configuring a static
// address before the interface exists (the ESP32-S3 demo's §22-4 trap).
//
#define ETH_LINK_TIMEOUT_S  30
#define ETH_DHCP_TIMEOUT_S  15
#define ETH_DHCP_ATTEMPTS   4

static void
ethernet_dhcp_wait(void)
{
	struct net_if *iface = net_if_get_default();
	struct net_mgmt_event_callback dhcp_cb;
	bool bound = false;
	int i, attempt;

	if (iface == NULL) {
		printk("eth: no network interface found\n");
		return;
	}

	printk("eth: waiting for link (up to %d s)\n", ETH_LINK_TIMEOUT_S);
	for (i = 0; i < ETH_LINK_TIMEOUT_S * 10 && !net_if_is_up(iface); i++) {
		k_msleep(100);
		if ((i % 50) == 49) {
			printk("eth: still no link after %d s (dormant=%d)\n",
			    (i + 1) / 10, net_if_is_dormant(iface));
		}
	}
	if (!net_if_is_up(iface)) {
		printk("eth: no link after %d s — check the cable, the PHY reset "
		    "line and the MDIO address (the driver logs the PHY ID and "
		    "link speed above)\n", ETH_LINK_TIMEOUT_S);
		return;
	}
	printk("eth: link up\n");

	// One callback per event: net_mgmt's dispatch compares the whole
	// layer-code field of mask vs event (subsys/net/ip/net_mgmt.c
	// mgmt_run_slist_callbacks), so OR'ing events from different
	// layer-codes into one mask silently drops every delivery.
	net_mgmt_init_event_callback(&dhcp_cb, net_event_handler,
	    NET_EVENT_IPV4_DHCP_BOUND);
	net_mgmt_add_event_callback(&dhcp_cb);

	for (attempt = 1; attempt <= ETH_DHCP_ATTEMPTS && !bound; attempt++) {
		printk("eth: starting DHCPv4 client (attempt %d)\n", attempt);
		(void) net_dhcpv4_start(iface); // outcome is the BOUND event
		bound = k_sem_take(&dhcp_bound_sem,
		    K_SECONDS(ETH_DHCP_TIMEOUT_S)) == 0;
		if (!bound) {
			printk("eth: no DHCPv4 lease within %d s\n",
			    ETH_DHCP_TIMEOUT_S);
		}
	}

	net_mgmt_del_event_callback(&dhcp_cb);
}

static void
dump_iface_ipv4_cb(struct net_if *iface, struct net_if_addr *ifaddr, void *user_data)
{
	char buf[NET_IPV4_ADDR_LEN];

	if (ifaddr->address.family == AF_INET &&
	    (ifaddr->addr_type == NET_ADDR_MANUAL || ifaddr->addr_type == NET_ADDR_DHCP)) {
		printk("net: ipv4 %s\n", net_addr_ntop(
			AF_INET, &ifaddr->address.in_addr, buf, sizeof(buf)));
	}
	ARG_UNUSED(iface);
	ARG_UNUSED(user_data);
}

static void
dump_iface_ipv4(struct net_if *iface)
{
	if (iface != NULL) {
		net_if_ipv4_addr_foreach(iface, dump_iface_ipv4_cb, NULL);
	}
}

static void
list_iface_cb(struct net_if *iface, void *user_data)
{
	const struct device *dev = net_if_get_device(iface);

	printk("net: iface %p dev=%s up=%d\n", (void *) iface,
	       dev == NULL ? "(null)" : dev->name, net_if_is_up(iface));
	if (user_data != NULL) {
		dump_iface_ipv4(iface);
	}
}

static void
dump_ifaces(void)
{
	net_if_foreach(list_iface_cb, (void *) 1);
}

#if defined(CONFIG_USB_DEVICE_NETWORK_ECM)
//
// USB-ECM bring-up (the ART-Pi's USB-OTG port, PA11/PA12).
//
// Here the board is the USB *device* and, because a host attaching to the
// other end has no reason to run a DHCP server, it is also the DHCPv4 server
// for the link: it puts a static address on the ECM interface, points the
// server's pool at the same subnet, and the host's network manager then
// configures the new "usb" interface by itself — no host-side privileges,
// no manual ip(8) step.
//
// Carrier (and therefore net_if_is_up()) only arrives once the host has
// enumerated the device and configured the ECM function, so the wait below
// doubles as the "did the cable find a host?" check.
#define USB_LINK_TIMEOUT_S 60

static void
usb_net_bringup(void)
{
	static struct net_in_addr board_addr = { { { 10, 10, 10, 1 } } };
	static struct net_in_addr netmask = { { { 255, 255, 255, 0 } } };
	struct net_in_addr pool_addr = { { { 10, 10, 10, 10 } } };
	struct net_if *iface = net_if_get_default();
	char buf[NET_IPV4_ADDR_LEN];
	int i, ret;

	if (iface == NULL) {
		printk("usb: no network interface found\n");
		return;
	}

	printk("usb: starting the device stack (CDC-ECM)\n");
	ret = usb_enable(NULL);
	if (ret != 0) {
		printk("usb: usb_enable failed (%d)\n", ret);
		return;
	}

	printk("usb: waiting for the host to attach (up to %d s)\n",
	    USB_LINK_TIMEOUT_S);
	for (i = 0; i < USB_LINK_TIMEOUT_S * 10 && !net_if_is_up(iface); i++) {
		k_msleep(100);
		if ((i % 100) == 99) {
			printk("usb: still no carrier after %d s\n", (i + 1) / 10);
		}
	}
	if (!net_if_is_up(iface)) {
		printk("usb: no carrier — plug the OTG port into a host\n");
		return;
	}
	printk("usb: carrier up\n");

	// Board address and netmask: the server derives the link's subnet from
	// this pair, and rejects a pool that is not inside it.
	if (net_if_ipv4_addr_add(iface, &board_addr, NET_ADDR_MANUAL, 0) == NULL) {
		printk("usb: could not add the board address\n");
	}
	(void) net_if_ipv4_set_netmask_by_addr(iface, &board_addr, &netmask);

	ret = net_dhcpv4_server_start(iface, &pool_addr);
	printk("usb: DHCPv4 server %s, board %s (host gets a lease from .10)\n",
	    ret == 0 ? "started" : "failed",
	    net_addr_ntop(AF_INET, &board_addr, buf, sizeof(buf)));
}
#endif /* CONFIG_USB_DEVICE_NETWORK_ECM */

#if defined(CONFIG_BROKER_SNTP)
// Public NTP servers, tried in order.  sntp_simple() already retries with
// exponential backoff inside its own timeout, so a single call per server
// rides out a burst of lost packets; the second entry only covers the first
// server being down.  Requires a resolver for the hostnames (the Kconfig
// option selects DNS_RESOLVER); switch to literal addresses to drop DNS.
static const char *const sntp_servers[] = {
	"ntp.aliyun.com",
	"cn.pool.ntp.org",
};

// Seed CLOCK_REALTIME so nanolib's log module (which formats time(NULL))
// stamps real dates instead of the 1970 epoch.  Best effort: with no server
// reachable the broker still starts, just with the wrong clock.  Rolled by
// hand rather than using Zephyr's net_init_clock_via_sntp() because that
// lives in the net_config directory, which is only added to the build by
// CONFIG_NET_CONFIG_SETTINGS — the module this demo deliberately avoids
// (see ethernet_dhcp_wait()).
static void
seed_realtime_from_sntp(void)
{
	for (size_t i = 0; i < ARRAY_SIZE(sntp_servers); i++) {
		struct sntp_time ts;

		if (sntp_simple(sntp_servers[i], 2000, &ts) == 0) {
			// NTP fractions are in units of 1/2^32 s — the same
			// conversion Zephyr's own helper applies.
			struct timespec t = {
				.tv_sec  = (time_t) ts.seconds,
				.tv_nsec = (long)
				    (((uint64_t) ts.fraction * NSEC_PER_SEC) >> 32),
			};

			(void) sys_clock_settime(SYS_CLOCK_REALTIME, &t);
			printk("sntp: %s: epoch=%lld, realtime seeded\n",
			    sntp_servers[i], (long long) t.tv_sec);
			return;
		}
		printk("sntp: %s: no reply\n", sntp_servers[i]);
	}
	printk("sntp: no server reachable, clock stays at the 1970 epoch\n");
}
#endif /* CONFIG_BROKER_SNTP */

#if defined(CONFIG_WIFI)
//
// Wi-Fi STA bring-up (the ART-Pi's AP6212 — an Infineon CYW43438 on SDMMC2).
//
// The driver enumerates the chip over SDIO and implements Zephyr's Wi-Fi mgmt
// API; connecting and getting a lease is the application's job, exactly as in
// the ESP32-S3 sibling demo.  Credentials come from app Kconfig
// (BROKER_WIFI_SSID / BROKER_WIFI_PSK), supplied through the git-ignored
// local.conf.
//
static K_SEM_DEFINE(wifi_connected_sem, 0, 1);
static K_SEM_DEFINE(wifi_dhcp_sem, 0, 1);

static void
wifi_mgmt_event_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
    struct net_if *iface)
{
	switch (mgmt_event) {
	case NET_EVENT_WIFI_CONNECT_RESULT: {
		struct wifi_status *st = (struct wifi_status *) cb->info;

		if (st != NULL && st->status == 0) {
			printk("wifi: connected to \"%s\"\n",
			    CONFIG_BROKER_WIFI_SSID);
			k_sem_give(&wifi_connected_sem);
		} else {
			printk("wifi: connect attempt failed (status %d)\n",
			    st == NULL ? -1 : st->status);
		}
		break;
	}
	case NET_EVENT_IPV4_DHCP_BOUND:
		printk("wifi: IPv4 address assigned (DHCPv4)\n");
		k_sem_give(&wifi_dhcp_sem);
		break;
	default:
		break;
	}
	ARG_UNUSED(cb);
	ARG_UNUSED(iface);
}

static int
wifi_sta_connect(void)
{
	const char *ssid = CONFIG_BROKER_WIFI_SSID;
	const char *psk  = CONFIG_BROKER_WIFI_PSK;
	struct wifi_connect_req_params cnx = { 0 };
	struct net_mgmt_event_callback wifi_cb;
	struct net_mgmt_event_callback dhcp_cb;
	struct net_if *iface;
	int ret;

	if (ssid[0] == '\0') {
		printk("wifi: BROKER_WIFI_SSID is empty (set it via local.conf) — "
		    "starting broker without Wi-Fi\n");
		return (-1);
	}
	// With the Ethernet node disabled in this build, the Wi-Fi interface is
	// the default one.
	iface = net_if_get_default();
	if (iface == NULL) {
		printk("wifi: no network interface found\n");
		return (-1);
	}

	cnx.ssid        = (const uint8_t *) ssid;
	cnx.ssid_length = strlen(ssid);
	cnx.channel     = WIFI_CHANNEL_ANY;
	cnx.band        = WIFI_FREQ_BAND_2_4_GHZ;
	cnx.security    = psk[0] != '\0' ? WIFI_SECURITY_TYPE_PSK
					 : WIFI_SECURITY_TYPE_NONE;
	cnx.psk         = (const uint8_t *) psk;
	cnx.psk_length  = strlen(psk);
	cnx.timeout     = 30000U;

	/* One callback per event: net_mgmt's dispatch compares the whole
	 * layer-code field of mask vs event (subsys/net/ip/net_mgmt.c
	 * mgmt_run_slist_callbacks), so OR'ing events from different
	 * layer-codes into one mask silently drops every delivery. */
	net_mgmt_init_event_callback(&wifi_cb, wifi_mgmt_event_handler,
	    NET_EVENT_WIFI_CONNECT_RESULT);
	net_mgmt_add_event_callback(&wifi_cb);
	net_mgmt_init_event_callback(&dhcp_cb, wifi_mgmt_event_handler,
	    NET_EVENT_IPV4_DHCP_BOUND);
	net_mgmt_add_event_callback(&dhcp_cb);

	// Bounded on purpose: the broker must start (and say so) even when the
	// link does not come up, otherwise a board that cannot associate shows
	// no broker log at all and looks dead.  The Ethernet and USB paths
	// below are bounded for the same reason.
#define WIFI_CONNECT_ATTEMPTS 3
	for (int tries = 1; tries <= WIFI_CONNECT_ATTEMPTS; tries++) {
		printk("wifi: connecting to \"%s\" (attempt %d)\n", ssid, tries);
		ret = net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &cnx,
		    sizeof(cnx));
		if (ret != 0) {
			printk("wifi: connect request failed (%d)\n", ret);
		}
		if (k_sem_take(&wifi_connected_sem, K_SECONDS(30)) == 0) {
			break;
		}
		if (tries == WIFI_CONNECT_ATTEMPTS) {
			/* Give up on the link, not on the broker: it starts and
			 * says so, because a board that cannot associate must
			 * still be visible on the console.  The DHCP client is
			 * started as well, so an address that turns up later --
			 * the chip joining on its own, say -- is picked up.  No
			 * one retries the association for us, so a reset is the
			 * way back. */
			printk("wifi: no association after %d attempts (%d s each) "
			    "— starting the broker anyway, but this link has no "
			    "address, so nothing can reach it yet.  Check the "
			    "credentials in local.conf, then reset the board to "
			    "retry.\n", WIFI_CONNECT_ATTEMPTS, 30);
			net_dhcpv4_start(iface);
			return (-1);
		}
		printk("wifi: connect timed out — retrying (iface up=%d "
		    "dormant=%d)\n", net_if_is_up(iface),
		    net_if_is_dormant(iface));
	}

	printk("wifi: connected — starting DHCPv4 client\n");
	net_dhcpv4_start(iface); // outcome arrives as the BOUND event
	if (k_sem_take(&wifi_dhcp_sem, K_SECONDS(30)) != 0) {
		printk("wifi: no DHCPv4 lease within 30 s\n");
	}

	net_mgmt_del_event_callback(&wifi_cb);
	net_mgmt_del_event_callback(&dhcp_cb);
	return (0);
}
#endif /* CONFIG_WIFI */

void
main(void)
{
	conf *nmq_conf;

#if defined(CONFIG_WIFI)
	wifi_sta_connect();
#elif defined(CONFIG_USB_DEVICE_NETWORK_ECM)
	usb_net_bringup();
#else
	ethernet_dhcp_wait();
#endif
#if defined(CONFIG_BROKER_SNTP)
	// Real wall clock before log_init()/broker() start printing
	// timestamps.  Must come after the DHCP wait above: SNTP needs an
	// address and a route.
	seed_realtime_from_sntp();
#endif
	dump_ifaces();

	if ((nmq_conf = nng_zalloc(sizeof(conf))) == NULL) {
		printk("Cannot allocate configuration, quit\n");
		return;
	}

	conf_init(nmq_conf);

	// Embedded minimal conf: defaults + key overrides.
	nmq_conf->url          = "nmq-tcp://0.0.0.0:1883";
	nmq_conf->ipc_internal = false; // cmd/reload server needs IPC transport
	nmq_conf->daemon       = false;
	// The QoS/keepalive/session machinery ticks on qos_duration (conf_init
	// default 10 s): offline-queued QoS>0 messages only become eligible for
	// redelivery after qos_duration*1.25 s (broker_tcp.c GET_QOS_RESEND) and
	// keepalive/session expiry are checked once per qos_duration.  Shorten
	// to 1 s so persistent-session & keepalive scenarios respond promptly.
	nmq_conf->qos_duration = 1;
	// MQTT 5 topic aliases.  conf_init leaves max_topic_alias 0, so the
	// CONNACK advertises TOPIC_ALIAS_MAXIMUM=0 and every PUBLISH carrying a
	// topic alias is rejected (pub_handler.c handle_pub → "Invalid Topic
	// Alias ... Server Max allowed: 0").  The host test conf sets 1024
	// (.github/scripts/nanomq.conf on master); mirror it so the CI v5
	// suite's topic-alias case means the same thing here.
	nmq_conf->max_topic_alias = 1024;
#ifdef CONFIG_BROKER_LOG_DEBUG
	nmq_conf->log.level    = NNG_LOG_DEBUG;
#endif

#ifdef CONFIG_BROKER_REST_API
	// REST API on plain HTTP with Basic auth.  broker() calls
	// start_rest_server() itself (apps/broker.c); the http server is a
	// separate TCP listener (conf default ip 0.0.0.0, port 8081) bridged
	// into the broker socket over inproc REQ/REP.
	//
	// auth_type defaults to BASIC, but conf_http_server_init() leaves
	// username/password NULL — and basic_authorize() (rest_api.c) does
	// strlen() on both, so the credentials must be filled in or the first
	// REST request dereferences NULL.  They come from Kconfig
	// (BROKER_REST_USER/PASS), which has no default: the board serves this
	// port to the whole LAN, so the listener stays off until the deployment
	// supplies credentials of its own.  The published admin/public pair is
	// refused unless CONFIG_BROKER_REST_ALLOW_PUBLISHED is set (a bench-only
	// switch, so function_test.py's defaults work without extra flags).
	//
	// NB: Basic over plain HTTP is base64, not encryption — TLS is compiled
	// out of the Zephyr NanoNNG, so keep this off untrusted networks.
	bool published = (strcmp(CONFIG_BROKER_REST_USER, "admin") == 0) &&
	    (strcmp(CONFIG_BROKER_REST_PASS, "public") == 0);

	if ((strlen(CONFIG_BROKER_REST_USER) > 0) &&
	    (strlen(CONFIG_BROKER_REST_PASS) > 0) &&
	    (!published || IS_ENABLED(CONFIG_BROKER_REST_ALLOW_PUBLISHED))) {
		nmq_conf->http_server.enable    = true;
		nmq_conf->http_server.auth_type = BASIC;
		nmq_conf->http_server.username =
		    nng_strdup(CONFIG_BROKER_REST_USER);
		nmq_conf->http_server.password =
		    nng_strdup(CONFIG_BROKER_REST_PASS);
	} else {
		printk("rest: REST API stays off - set "
		    "CONFIG_BROKER_REST_USER and CONFIG_BROKER_REST_PASS to "
		    "credentials of your own (local.conf), or set "
		    "CONFIG_BROKER_REST_ALLOW_PUBLISHED=y to accept the "
		    "published admin/public pair\n");
	}
#endif

#ifdef CONFIG_BROKER_WS
	// WebSocket listener (MQTT over RFC6455, paho's default path /mqtt).
	// broker() listens on websocket.url verbatim — the CONF_WS_URL_DEFAULT
	// fallback lives in the broker_start*() file path, which this demo
	// bypasses — so both fields must be set here.  TLS is compiled out of
	// the Zephyr NanoNNG, so the wss: sibling listener stays inert.
	nmq_conf->websocket.enable = true;
	nmq_conf->websocket.url    = "nmq-ws://0.0.0.0:8083/mqtt";
#endif

#ifdef CONFIG_BROKER_WEBHOOK
	// Webhook forwarder: broker pushes event JSON into the hook channel and
	// a dedicated thread POSTs it to web_hook.url with the nng HTTP client
	// (fire-and-forget; slow receivers never block the broker).  The default
	// hook channel is ipc:///tmp/... — Zephyr has no IPC transport, so it
	// must be inproc.  The receiver URL has no sensible default on a real
	// board: it must be the LAN address of the machine running
	// hook_receiver.py, set via CONFIG_BROKER_WEBHOOK_URL in local.conf.
	if (strlen(CONFIG_BROKER_WEBHOOK_URL) > 0) {
		// Every allocation here can fail and the rules are filled in
		// field by field, so build them first and only switch the
		// forwarder on once all of them succeeded.  nng_free(NULL, ...)
		// is a no-op, so the failure path can free unconditionally.
		conf_web_hook_rule *hook_msg =
		    nng_zalloc(sizeof(conf_web_hook_rule));
		conf_web_hook_rule *hook_conn =
		    nng_zalloc(sizeof(conf_web_hook_rule));
		conf_web_hook_rule **rules =
		    nng_zalloc(2 * sizeof(conf_web_hook_rule *));
		char *hook_topic = nng_strdup("hook/#");

		if (hook_msg != NULL && hook_conn != NULL && rules != NULL &&
		    hook_topic != NULL) {
			hook_msg->event  = MESSAGE_PUBLISH; // every publish
			hook_msg->topic  = hook_topic;
			hook_conn->event = CLIENT_CONNACK;  // every connect
			rules[0]         = hook_msg;
			rules[1]         = hook_conn;

			nmq_conf->web_hook.enable     = true;
			nmq_conf->web_hook.url =
			    nng_strdup(CONFIG_BROKER_WEBHOOK_URL);
			nmq_conf->hook_ipc_url =
			    nng_strdup("inproc://nanomq_hook");
			nmq_conf->web_hook.rules      = rules;
			nmq_conf->web_hook.rule_count = 2;
		} else {
			printk("webhook: allocation failed, forwarder stays off\n");
			nng_free(hook_msg, sizeof(conf_web_hook_rule));
			nng_free(hook_conn, sizeof(conf_web_hook_rule));
			nng_free(rules, 2 * sizeof(conf_web_hook_rule *));
			nng_free(hook_topic, sizeof("hook/#"));
		}
	}
#endif

#if defined(ENABLE_LOG)
	// Activate the nanolib log backend (console) and apply conf->log.level —
	// broker_start_with_conf() normally does this, but the embedded demo
	// calls broker() directly.
	//
	// nanomq's log_init() (mqtt_api.c) applies log->level and registers the
	// console sink itself, since conf_init() defaults log.type to
	// LOG_TO_CONSOLE.  Registering one here as well would add a second sink
	// and print every line twice.
	//
	// Console at INFO by default: CONFIG_BROKER_LOG_DEBUG raises it when the
	// per-packet tracing is what you are after (it makes the 115200 console
	// the throughput bottleneck).
	nmq_conf->log.level = NNG_LOG_INFO;
#ifdef CONFIG_BROKER_LOG_DEBUG
	nmq_conf->log.level = NNG_LOG_DEBUG;
	print_conf(nmq_conf);
#endif
	(void) log_init(&nmq_conf->log);
#endif

	/* Let the status thread start reporting — see
	 * CONFIG_BROKER_STATUS_INTERVAL_S. */
	broker_running = true;

	broker(nmq_conf);

	// broker() only returns on (unreachable) test paths.
	printk("NanoMQ broker exited unexpectedly\n");
}
