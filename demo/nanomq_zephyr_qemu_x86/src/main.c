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
#include <zephyr/sys/clock.h>
#include <string.h>

#include "nng/nng.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/nanolib/log.h"
#include "mqtt_api.h" // log_init(conf_log *)

#if defined(CONFIG_X86)
#include <time.h>              // time_t
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
	uint8_t v;

	// Bit 7 of the index byte disables NMI while addressing the RTC.
	// Re-select the same register with bit 7 clear afterwards, so the
	// broker does not leave the CPU's NMI masked for the rest of the run.
	sys_out8((uint8_t) (reg | 0x80U), CMOS_PORT_IDX);
	v = sys_in8(CMOS_PORT_DAT);
	sys_out8(reg, CMOS_PORT_IDX);
	return v;
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

	if (ifaddr->address.family == AF_INET && ifaddr->addr_type == NET_ADDR_MANUAL) {
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
	// strlen() on both, so the credentials must be filled in or the first
	// REST request dereferences NULL.  They come from Kconfig
	// (BROKER_REST_USER/PASS), which has no default: this is an
	// administrative surface on a port the host forwards, so the listener
	// stays off until the deployment supplies credentials of its own.  The
	// published admin/public pair is refused rather than warned about.
	//
	// NB: Basic over plain HTTP is base64, not encryption — TLS is
	// compiled out of the Zephyr NanoNNG, so keep this off untrusted
	// networks regardless.
	if ((strlen(CONFIG_BROKER_REST_USER) > 0) &&
	    (strlen(CONFIG_BROKER_REST_PASS) > 0) &&
	    !((strcmp(CONFIG_BROKER_REST_USER, "admin") == 0) &&
	        (strcmp(CONFIG_BROKER_REST_PASS, "public") == 0))) {
		nmq_conf->http_server.enable    = true;
		nmq_conf->http_server.auth_type = BASIC;
		nmq_conf->http_server.username =
		    nng_strdup(CONFIG_BROKER_REST_USER);
		nmq_conf->http_server.password =
		    nng_strdup(CONFIG_BROKER_REST_PASS);
	} else {
		printk("rest: REST API stays off - set "
		    "CONFIG_BROKER_REST_USER and CONFIG_BROKER_REST_PASS to "
		    "credentials of your own (local.conf); the published "
		    "admin/public pair is refused\n");
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
	// The receiver URL is a build-time setting (CONFIG_BROKER_WEBHOOK_URL):
	// 10.0.2.2 is the SLIRP alias for the machine running qemu, so a
	// receiver started there works as-is.  With the URL left empty the
	// forwarder stays disabled rather than POSTing into the void.
	if (strlen(CONFIG_BROKER_WEBHOOK_URL) > 0) {
		// Every allocation here can fail and the rules are filled in field
		// by field, so build them first and only switch the forwarder on
		// once all of them succeeded.  nng_free(NULL, ...) is a no-op, so
		// the failure path can free unconditionally.
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
	// Activate the nanolib log backend (console) and apply conf->log.level
	// — broker_start_with_conf() normally does this, but the embedded demo
	// calls broker() directly.
	log_init(&nmq_conf->log);
	// Use the configured level rather than a fixed WARN: with
	// CONFIG_BROKER_LOG_DEBUG the level set above is DEBUG, and a
	// hard-coded WARN sink filters everything below it straight back out.
	log_add_console(nmq_conf->log.level, NULL);
#endif

	broker(nmq_conf);

	// broker() only returns on (unreachable) test paths.
	printk("NanoMQ broker exited unexpectedly\n");
}
