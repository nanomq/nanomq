//
// Zephyr broker entry point — "embedded minimal conf" bootstrap.
//
// Zephyr has no filesystem, so the broker is started with conf_init()
// defaults plus a few field overrides, then broker() is called directly.
// broker_start() (file parsing, daemonize) is deliberately bypassed.
//
// Startup contract with apps/broker.c::broker(conf *):
//   * conf->url non-NULL  → broker listens on it (nmq-tcp:// ...)
//   * conf->ipc_internal  → cmd server over IPC transport; Zephyr build
//                           has NNG_TRANSPORT_IPC=OFF, so it must be false
//   * log_init() must run first: in the normal flow it is called by
//     broker_start_with_conf() right before broker(); broker() itself
//     never touches the nanolib log module
//   * broker() never returns: it parks in for(;;) nng_msleep(3600000)
//
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/sntp.h> // sntp_simple() — clock seed
#include <zephyr/sys/clock.h>

#if !defined(CONFIG_X86)
#include <string.h>
#include <zephyr/net/dhcpv4.h>
#include <zephyr/net/net_event.h>
#include <zephyr/net/wifi_mgmt.h>
#endif

#include "nng/nng.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/nanolib/log.h"
#include "mqtt_api.h" // log_init(conf_log *)

#include <time.h> // struct timespec/time_t — CMOS seed and SNTP seed

#if defined(CONFIG_X86)
#include <zephyr/sys/sys_io.h> // io_port_t
#include <zephyr/arch/x86/arch.h> // sys_in8()/sys_out8()
#endif

// broker() lives in nanomq/nanomq/apps/broker.c and is not declared in
// broker.h (which only exports broker_start/broker_start_with_conf).
extern int broker(conf *nanomq_conf);

#if defined(CONFIG_X86)
//
// Seed CLOCK_REALTIME from the QEMU-emulated mc146818 (CMOS) RTC.
//
// Zephyr has no timeprovider wired to the PC CMOS RTC, so CLOCK_REALTIME
// starts at the 1970 epoch and nanolib's log timestamps (log.c formats
// time(NULL) with localtime_r) print "1970-01-01 00:00:xx + uptime".
// QEMU's q35 chipset emulates the standard CMOS RTC at I/O ports 0x70/0x71
// and seeds it with the host clock at launch (default `-rtc base=utc`),
// so reading it once at boot and handing it to sys_clock_settime() gives
// real timestamps from then on (lib/os/clock.c: realtime = offset+uptime,
// so the clock keeps tracking without further updates).
//

#define CMOS_PORT_IDX   0x70U
#define CMOS_PORT_DAT   0x71U
#define CMOS_REG_SEC    0x00U
#define CMOS_REG_MIN    0x02U
#define CMOS_REG_HOUR   0x04U
#define CMOS_REG_DAY    0x07U
#define CMOS_REG_MON    0x08U
#define CMOS_REG_YEAR   0x09U
#define CMOS_REG_STAT_A 0x0AU
#define CMOS_REG_STAT_B 0x0BU
#define CMOS_UIP_BIT    0x80U /* STAT_A: update in progress */
#define CMOS_24H_BIT    0x02U /* STAT_B: 0 = 12 h mode */
#define CMOS_BIN_BIT    0x04U /* STAT_B: 0 = BCD, 1 = binary */

static uint8_t
cmos_read(uint8_t reg)
{
	// Bit 7 of the index byte disables NMI while addressing the RTC.
	sys_out8((uint8_t) (reg | 0x80U), CMOS_PORT_IDX);
	return sys_in8(CMOS_PORT_DAT);
}

static uint8_t
cmos_bcd2bin(uint8_t v)
{
	return (uint8_t) (((v >> 4) & 0x0FU) * 10U + (v & 0x0FU));
}

// days_from_civil(): Howard Hinnant's algorithm, proleptic Gregorian —
// avoids libc mktime()/TZ involvement (the CMOS clock is UTC).
static int64_t
days_from_civil(int64_t y, unsigned m, unsigned d)
{
	int64_t era;
	unsigned yoe, doe, doy;

	y -= (m <= 2U);
	era = (y >= 0 ? y : y - 399) / 400;
	yoe = (unsigned) (y - era * 400);
	doy = (153U * (m + (m > 2U ? -3U : 9U)) + 2U) / 5U + d - 1U;
	doe = yoe * 365U + yoe / 4U - yoe / 100U + doy;

	return era * 146097 + (int64_t) doe - 719468;
}

static int
cmos_read_datetime(uint8_t *secp, uint8_t *minp, uint8_t *hourp, uint8_t *dayp,
    uint8_t *monp, uint8_t *yearp)
{
	uint8_t s1, s2;
	int     i;

	// Re-read until the seconds register is stable across the whole
	// read (the RTC updates once per second; reads must not straddle it).
	for (i = 0; i < 8; i++) {
		s1    = cmos_read(CMOS_REG_SEC);
		*minp = cmos_read(CMOS_REG_MIN);
		*hourp = cmos_read(CMOS_REG_HOUR);
		*dayp = cmos_read(CMOS_REG_DAY);
		*monp = cmos_read(CMOS_REG_MON);
		*yearp = cmos_read(CMOS_REG_YEAR);
		s2    = cmos_read(CMOS_REG_SEC);
		if (s1 == s2) {
			*secp = s1;
			return (0);
		}
	}

	return (-1);
}

static void
seed_realtime_from_cmos(void)
{
	struct timespec ts;
	uint8_t sec, min, hour, day, mon, year, stat_b;
	bool binary, h24, pm = false;
	unsigned tries, y_full;
	int64_t epoch;

	// Wait out any update-in-progress cycle before touching the regs.
	for (tries = 0; tries < 1000; tries++) {
		if ((cmos_read(CMOS_REG_STAT_A) & CMOS_UIP_BIT) == 0U) {
			break;
		}
	}
	if (cmos_read_datetime(&sec, &min, &hour, &day, &mon, &year) != 0) {
		printk("rtc: CMOS read straddled an update, keeping 1970 epoch\n");
		return;
	}
	stat_b = cmos_read(CMOS_REG_STAT_B);
	binary = (stat_b & CMOS_BIN_BIT) != 0;
	h24    = (stat_b & CMOS_24H_BIT) != 0;

	// 12 h mode keeps the PM flag in bit 7 of the hour register.  Take it
	// off before the BCD conversion: cmos_bcd2bin(0x92) would otherwise
	// turn 12 PM into 92 and the range check below would reject it.
	if (!h24) {
		pm = (hour & 0x80U) != 0;
		hour &= 0x7FU;
	}

	if (!binary) {
		sec  = cmos_bcd2bin(sec);
		min  = cmos_bcd2bin(min);
		hour = cmos_bcd2bin(hour);
		day  = cmos_bcd2bin(day);
		mon  = cmos_bcd2bin(mon);
		year = cmos_bcd2bin(year);
	}
	if (!h24) {
		if (pm) {
			if (hour != 12U) {
				hour += 12U;
			}
		} else if (hour == 12U) {
			hour = 0;
		}
	}

	// Sanity checks: 2-digit year mapped onto 1970-2069, valid date.
	y_full = (year >= 70U) ? (1900U + year) : (2000U + year);
	if (y_full < 2000U || y_full > 2099U || mon < 1U || mon > 12U ||
	    day < 1U || day > 31U || hour > 23U || min > 59U || sec > 59U) {
		printk("rtc: CMOS time out of range (%04u-%02u-%02u %02u:%02u:%02u)\n",
		    y_full, mon, day, hour, min, sec);
		return;
	}
	epoch = days_from_civil(y_full, mon, day) * 86400 +
	    hour * 3600 + min * 60 + sec;

	ts.tv_sec  = (time_t) epoch;
	ts.tv_nsec = 0;
	(void) sys_clock_settime(SYS_CLOCK_REALTIME, &ts);

	printk("rtc: CMOS clock %04u-%02u-%02u %02u:%02u:%02u UTC, realtime seeded\n",
	    y_full, mon, day, hour, min, sec);
}
#endif // CONFIG_X86

static void
dump_iface_ipv4_cb(struct net_if *iface, struct net_if_addr *ifaddr, void *user_data)
{
	char buf[NET_IPV4_ADDR_LEN];

	// qemu demo: NET_ADDR_MANUAL (static); ESP32-S3 demo: NET_ADDR_DHCP.
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

#if defined(CONFIG_WIFI_ESP32)
//
// Wi-Fi STA + DHCPv4 bring-up (ESP32-S3 demo; the qemu_x86 demo has no
// Wi-Fi).  The broker binds 0.0.0.0 listeners, but there is nothing to
// accept connections from until the Wi-Fi link is up and has an IPv4
// address, so main() runs this before broker().
//
// Credentials come from app Kconfig (BROKER_WIFI_SSID / BROKER_WIFI_PSK)
// and are meant to be supplied through a local, git-ignored conf file
// (see local.conf.example) — real SSID/passphrases stay out of the tree.

static K_SEM_DEFINE(wifi_connected_sem, 0, 1);
static K_SEM_DEFINE(dhcp_bound_sem, 0, 1);

static void
wifi_mgmt_event_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
    struct net_if *iface)
{
	switch (mgmt_event) {
	case NET_EVENT_WIFI_CONNECT_RESULT: {
		struct wifi_status *st = (struct wifi_status *) cb->info;

		if (st != NULL && st->status == 0) {
			printk("wifi: connected to \"%s\"\n", CONFIG_BROKER_WIFI_SSID);
			k_sem_give(&wifi_connected_sem);
		} else {
			printk("wifi: connect attempt failed (status %d)\n",
			    st == NULL ? -1 : st->status);
		}
		break;
	}
#if defined(CONFIG_NET_DHCPV4)
	case NET_EVENT_IPV4_DHCP_BOUND:
		printk("wifi: IPv4 address assigned (DHCPv4)\n");
		k_sem_give(&dhcp_bound_sem);
		break;
#endif
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
	// Single Wi-Fi iface on this board — the default iface is it.
	iface = net_if_get_default();
	if (iface == NULL) {
		printk("wifi: no network interface found\n");
		return (-1);
	}

	cnx.ssid        = (const uint8_t *) ssid;
	cnx.ssid_length = strlen(ssid);
	cnx.channel     = WIFI_CHANNEL_ANY;
	cnx.band        = WIFI_FREQ_BAND_2_4_GHZ;
	cnx.security    = psk[0] != '\0' ? WIFI_SECURITY_TYPE_PSK : WIFI_SECURITY_TYPE_NONE;
	cnx.psk         = (const uint8_t *) psk;
	cnx.psk_length  = strlen(psk);
	cnx.timeout     = 30000U; /* ms — the wifi driver needs a finite timeout */

	/* One callback per event: net_mgmt's dispatch compares the whole
	 * layer-code field of mask vs event (subsys/net/ip/net_mgmt.c
	 * mgmt_run_slist_callbacks), so OR'ing events from different
	 * layer-codes into one mask silently drops every delivery. */
	net_mgmt_init_event_callback(&wifi_cb, wifi_mgmt_event_handler,
	    NET_EVENT_WIFI_CONNECT_RESULT);
	net_mgmt_add_event_callback(&wifi_cb);
#if defined(CONFIG_NET_DHCPV4)
	net_mgmt_init_event_callback(&dhcp_cb, wifi_mgmt_event_handler,
	    NET_EVENT_IPV4_DHCP_BOUND);
	net_mgmt_add_event_callback(&dhcp_cb);
#endif

	for (int tries = 1;; tries++) {
		printk("wifi: connecting to \"%s\" (attempt %d)\n", ssid, tries);
		ret = net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &cnx, sizeof(cnx));
		if (ret != 0) {
			printk("wifi: connect request failed (%d)\n", ret);
		}
		if (k_sem_take(&wifi_connected_sem, K_SECONDS(30)) == 0) {
			break;
		}
		printk("wifi: connect timed out — retrying (iface up=%d dormant=%d)\n",
		    net_if_is_up(iface), net_if_is_dormant(iface));
	}

#if defined(CONFIG_NET_DHCPV4)
	printk("wifi: connected — starting DHCPv4 client\n");
	net_dhcpv4_start(iface); // void on this Zephyr; outcome is the BOUND event
	if (k_sem_take(&dhcp_bound_sem, K_SECONDS(30)) != 0) {
		printk("wifi: no DHCPv4 lease within 30 s\n");
	}
#endif

	net_mgmt_del_event_callback(&wifi_cb);
#if defined(CONFIG_NET_DHCPV4)
	net_mgmt_del_event_callback(&dhcp_cb);
#endif
	return (0);
}
#endif /* CONFIG_WIFI_ESP32 */

#if defined(CONFIG_SNTP)
// Public NTP servers, tried in order.  sntp_simple() already retries with
// exponential backoff inside its own timeout (subsys/net/lib/sntp/
// sntp_simple.c), so a single call per server rides out a burst of lost
// packets; the second entry only covers the first server being down.
static const char *const sntp_servers[] = {
	"ntp.aliyun.com",
	"cn.pool.ntp.org",
};

// Seed CLOCK_REALTIME so that nanolib's log module (which formats
// time(NULL), log.c) stamps real dates instead of the 1970 epoch.  Best
// effort: with no server reachable the broker still starts, just with the
// wrong clock.  We roll this by hand instead of calling Zephyr's
// net_init_clock_via_sntp() because that lives in net_config, a directory
// only added to the build by CONFIG_NET_CONFIG_SETTINGS (see prj.conf and
// PORTING_ZEPHYR.md §22-4).
static void
seed_realtime_from_sntp(void)
{
	// Two passes with a pause in between: the likeliest failure right
	// after DHCP binds is the resolver not being ready yet, and that
	// fails immediately rather than consuming the timeout.
	for (int pass = 0; pass < 2; pass++) {
		for (size_t i = 0; i < ARRAY_SIZE(sntp_servers); i++) {
			struct sntp_time ts;

			if (sntp_simple(sntp_servers[i], 2000, &ts) == 0) {
				// NTP fractions are in units of 1/2^32 s —
				// the same conversion Zephyr's own
				// net_init_clock_via_sntp() applies.
				struct timespec t = {
					.tv_sec  = (time_t) ts.seconds,
					.tv_nsec = (long)
					    (((uint64_t) ts.fraction *
					    NSEC_PER_SEC) >> 32),
				};

				(void) sys_clock_settime(
				    SYS_CLOCK_REALTIME, &t);
				printk("sntp: %s: epoch=%lld, realtime seeded\n",
				    sntp_servers[i], (long long) t.tv_sec);
				return;
			}
			printk("sntp: %s: no reply\n", sntp_servers[i]);
		}
		if (pass == 0) {
			k_msleep(1000);
		}
	}

	printk("sntp: no server reachable, clock stays at the 1970 epoch\n");
}
#endif /* CONFIG_SNTP */

void
main(void)
{
	conf *nmq_conf;

#if defined(CONFIG_X86)
	// Real wall clock before the broker (and nanolib log_init) starts
	// printing timestamps.
	seed_realtime_from_cmos();
#endif

	if ((nmq_conf = nng_zalloc(sizeof(conf))) == NULL) {
		printk("Cannot allocate configuration, quit\n");
		return;
	}

	conf_init(nmq_conf);


#if defined(CONFIG_WIFI_ESP32)
	// Wi-Fi first: the broker's 0.0.0.0 listeners are only reachable
	// once the link is up and DHCP has assigned an address.  qemu_x86
	// (the sibling demo) takes the static-IP path in prj.conf instead.
	if (wifi_sta_connect() != 0) {
		printk("net: broker starting without a network interface\n");
	}
#endif

#if defined(CONFIG_SNTP)
	// Real wall clock before log_init()/broker() start printing
	// timestamps.  Must come after the Wi-Fi/DHCP wait above: SNTP needs a
	// route, an address and a working DNS resolver.
	seed_realtime_from_sntp();
#endif
	dump_ifaces();

	// Embedded minimal conf: defaults + key overrides.
	nmq_conf->url          = "nmq-tcp://0.0.0.0:1883";
	nmq_conf->ipc_internal = false; // cmd/reload server needs IPC transport
	nmq_conf->daemon       = false;
	// The QoS/keepalive/session machinery ticks on qos_duration (conf_init
	// default 10s): offline-queued QoS>0 messages only become eligible for
	// redelivery after qos_duration*1.25s (broker_tcp.c GET_QOS_RESEND) and
	// keepalive/session expiry are checked once per qos_duration.  Shorten
	// to 1s so persistent-session & keepalive scenarios respond promptly.
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
	// strlen() on both, so the credentials must be filled in here or the
	// first REST request dereferences NULL.  They come from Kconfig
	// (BROKER_REST_USER/PASS) rather than from this file, so the board can
	// take deployment credentials from local.conf without patching C.
	//
	// NB: Basic over plain HTTP is base64, not encryption — TLS is
	// compiled out of the Zephyr NanoNNG, so keep this off untrusted
	// networks regardless.
	nmq_conf->http_server.enable    = true;
	nmq_conf->http_server.auth_type = BASIC;
	nmq_conf->http_server.username  = nng_strdup(CONFIG_BROKER_REST_USER);
	nmq_conf->http_server.password  = nng_strdup(CONFIG_BROKER_REST_PASS);

	if (strcmp(CONFIG_BROKER_REST_USER, "admin") == 0 &&
	    strcmp(CONFIG_BROKER_REST_PASS, "public") == 0) {
		printk("rest: WARNING serving tcp:8081 on the LAN with the "
		    "published default credentials admin/public - set "
		    "CONFIG_BROKER_REST_USER/PASS (local.conf) before "
		    "exposing this board\n");
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
	// Webhook forwarder: broker pushes event JSON into the hook channel
	// and a dedicated thread POSTs it to web_hook.url with the nng HTTP
	// client (fire-and-forget; slow receivers never block the broker).
	// The default hook channel is ipc:///tmp/... — Zephyr has no IPC
	// transport (NNG_TRANSPORT_IPC=OFF), so it must be inproc.
	//
	// The receiver URL is a build-time setting (CONFIG_BROKER_WEBHOOK_URL)
	// and has no sensible default on a real board: it must be the LAN
	// address of the machine running hook_receiver.py, so set it in
	// local.conf alongside the Wi-Fi credentials.  With the URL left empty
	// the forwarder stays disabled rather than POSTing into the void.
	if (strlen(CONFIG_BROKER_WEBHOOK_URL) > 0) {
		nmq_conf->web_hook.enable = true;
		nmq_conf->web_hook.url =
		    nng_strdup(CONFIG_BROKER_WEBHOOK_URL);
		nmq_conf->hook_ipc_url = nng_strdup("inproc://nanomq_hook");

		conf_web_hook_rule *hook_msg =
		    nng_zalloc(sizeof(conf_web_hook_rule));
		hook_msg->event = MESSAGE_PUBLISH; // fire on every publish
		hook_msg->topic = nng_strdup("hook/#");
		conf_web_hook_rule *hook_conn =
		    nng_zalloc(sizeof(conf_web_hook_rule));
		hook_conn->event = CLIENT_CONNACK; // fire when a client connects

		nmq_conf->web_hook.rules =
		    nng_zalloc(2 * sizeof(conf_web_hook_rule *));
		nmq_conf->web_hook.rules[0]   = hook_msg;
		nmq_conf->web_hook.rules[1]   = hook_conn;
		nmq_conf->web_hook.rule_count = 2;
	}
#endif

#if defined(ENABLE_LOG)
	// Activate the nanolib log backend (console) and apply conf->log.level
	// — broker_start_with_conf() normally does this, but the embedded demo
	// calls broker() directly.
	log_init(&nmq_conf->log);
	log_add_console(NNG_LOG_DEBUG, NULL);
	print_conf(nmq_conf);
#endif



	broker(nmq_conf);

	// broker() only returns on (unreachable) test paths.
	printk("NanoMQ broker exited unexpectedly\n");
}
