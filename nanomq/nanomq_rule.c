#include "include/nanomq_rule.h"
#include "nng/supplemental/nanolib/log.h"
#include "nng/mqtt/mqtt_client.h"
#include "nng/nng.h"
#include "nng/protocol/mqtt/mqtt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nng/supplemental/nanolib/cvector.h"
#include "nng/supplemental/nanolib/utils.h"

#include "include/nanomq.h"

#if defined(SUPP_RULE_ENGINE)

static char *key_arr[] = {
	"Qos",
	"Id",
	"Topic",
	"Clientid",
	"Username",
	"Password",
	"Timestamp",
	"Payload",
};

#if defined(SUPP_TIMESCALEDB)
static char *ts_type_arr[] = {
	" INT",
	" INT",
	" TEXT",
	" TEXT",
	" TEXT",
	" TEXT",
	" TIMESTAMPTZ NOT NULL",
	" TEXT",
};
#endif

static char *type_arr[] = {
	" INT",
	" INT",
	" TEXT",
	" TEXT",
	" TEXT",
	" TEXT",
	" INT",
	" TEXT",
};

int
nano_client_publish(nng_socket *sock, const char *topic, uint8_t *payload,
    uint32_t len, uint8_t qos, property *props)
{
	int rv;

	// create a PUBLISH message
	nng_msg *pubmsg;
	nng_mqtt_msg_alloc(&pubmsg, 0);
	nng_mqtt_msg_set_packet_type(pubmsg, NNG_MQTT_PUBLISH);
	nng_mqtt_msg_set_publish_dup(pubmsg, true);
	nng_mqtt_msg_set_publish_qos(pubmsg, qos);
	nng_mqtt_msg_set_publish_payload(pubmsg, payload, len);
	nng_mqtt_msg_set_publish_topic(pubmsg, topic);
	if (props) {
		nng_mqtt_msg_set_publish_property(pubmsg, props);
	}

	if ((rv = nng_sendmsg(*sock, pubmsg, NNG_FLAG_ALLOC)) != 0) {
		log_debug("nng_sendmsg failed %s", nng_strerror(rv));
	}

	return 0;
}

static void
disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	int reason = 0;
	// get disconnect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_DISCONNECT_REASON, &reason);
	log_debug("nano client disconnected! RC [%d] \n", reason);
}

// Connack message callback function
static void
connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	log_debug("nano client connected!\n");
}

int
nano_client(nng_socket *sock, repub_t *repub)
{
	int        rv;
	nng_dialer dialer;

	if (repub->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
		if ((rv = nng_mqttv5_client_open(sock)) != 0) {
			log_error("nng_mqttv5_client_open: %d", rv);
			return rv;
		}
	} else {
		if ((rv = nng_mqtt_client_open(sock)) != 0) {
			log_error("nng_mqtt_client_open: %d", rv);
			return rv;
		}
	}

	if ((rv = nng_dialer_create(&dialer, *sock, repub->address))) {
		log_error("Unsupport prefix: %s", repub->address);
		return rv;
	}

	// create a CONNECT message
	/* CONNECT */
	nng_msg *connmsg;
	nng_mqtt_msg_alloc(&connmsg, 0);
	nng_mqtt_msg_set_packet_type(connmsg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_keep_alive(connmsg, repub->keepalive);
	nng_mqtt_msg_set_connect_proto_version(connmsg, repub->proto_ver);
	nng_mqtt_msg_set_connect_clean_session(connmsg, repub->clean_start);
	if (repub->clientid) {
		nng_mqtt_msg_set_connect_client_id(connmsg, repub->clientid);
	}
	if (repub->username) {
		nng_mqtt_msg_set_connect_user_name(connmsg, repub->username);
	}
	if (repub->password) {
		nng_mqtt_msg_set_connect_password(connmsg, repub->password);
	}

	repub->sock = (void *) sock;

	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, connmsg);
	nng_mqtt_set_connect_cb(*sock, connect_cb, repub);
	nng_mqtt_set_disconnect_cb(*sock, disconnect_cb, connmsg);

	rv = nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	return rv;
}


#if defined(NNG_SUPP_SQLITE)
int
nanomq_client_sqlite(conf_rule *cr, bool init_last)
{
	sqlite3 *sdb;
	int      rc = 0;
	if (NULL == cr->rdb[0]) {
		char *sqlite_path = cr->sqlite_db
		    ? cr->sqlite_db
		    : "/tmp/rule_engine.db";
		rc                = sqlite3_open(sqlite_path, &sdb);
		if (rc != SQLITE_OK) {
			log_debug("Cannot open database: %s\n",
			    sqlite3_errmsg(sdb));
			sqlite3_close(sdb);
			return 1;
		}
		cr->rdb[0] = (void *) sdb;
	}

	char sqlite_table[1024];
	for (int i = 0; i < cvector_size(cr->rules); i++) {
		if (init_last && i != cvector_size(cr->rules) - 1) {
			continue;
		}
		if (RULE_FORWORD_SQLITE == cr->rules[i].forword_type) {
			int  index      = 0;
			char table[256] = { 0 };

			snprintf(table, 128,
			    "CREATE TABLE IF NOT EXISTS %s("
			    "RowId INTEGER PRIMARY KEY AUTOINCREMENT",
			    cr->rules[i].sqlite_table);
			char *err_msg = NULL;
			bool  first   = true;

			for (; index < 8; index++) {
				if (!cr->rules[i].flag[index])
					continue;

				strcat(table, ", ");
				strcat(table,
				    cr->rules[i].as[index]
				        ? cr->rules[i].as[index]
				        : key_arr[index]);
				strcat(table, type_arr[index]);
			}
			strcat(table, ");");
			// puts(table);
			rc = sqlite3_exec(cr->rdb[0], table, 0, 0, &err_msg);
			if (rc != SQLITE_OK) {
				log_error("SQL error: %s\n", err_msg);
				sqlite3_free(err_msg);
				sqlite3_close(sdb);
				return 1;
			}
		}
	}

	return 0;
}

#endif


#if defined(SUPP_POSTGRESQL) || defined(SUPP_TIMESCALEDB)
#include <libpq-fe.h>
#endif

#if defined(SUPP_TIMESCALEDB)

static int ts_finish_with_error(PGconn *conn, rule *rules, int index)
{
	log_error("timescaledb %s", PQerrorMessage(conn));
	PQfinish(conn);
	rule *r = &rules[index];
	rule_timescaledb_free(r->timescaledb);
	rule_free(r);
	cvector_erase(rules, index);
	return -1;
}

int
nanomq_client_timescaledb(conf_rule *cr, bool init_last)
{
	int      rc = 0;

	char timescaledb_table[1024];
	for (int i = 0; i < cvector_size(cr->rules); i++) {
		if (init_last && i != cvector_size(cr->rules) - 1) {
			continue;
		}
		if (RULE_FORWORD_TIMESCALEDB == cr->rules[i].forword_type) {
			int  index      = 0;
			char table[256] = { 0 };

			snprintf(table, 128,
			    "CREATE TABLE IF NOT EXISTS %s("
			    "idx BIGSERIAL",
			    cr->rules[i].timescaledb->table);

			char *err_msg = NULL;
			bool  first   = true;

			for (; index < 8; index++) {
				if (!cr->rules[i].flag[index])
					continue;

				strcat(table, ", ");
				strcat(table,
				    cr->rules[i].as[index]
				        ? cr->rules[i].as[index]
				        : key_arr[index]);
				strcat(table, ts_type_arr[index]);
			}
			strcat(table, ");");

			rule_timescaledb *timescaledb = cr->rules[i].timescaledb;

			char conninfo[256] = { 0 };
			snprintf(conninfo , 128, "dbname=postgres user=%s password=%s host=%s port=5432", timescaledb->username, timescaledb->password, timescaledb->host);
			PGconn *conn = PQconnectdb(conninfo);

			if (PQstatus(conn) != CONNECTION_OK) {
				rc = ts_finish_with_error(conn, cr->rules, i--);
				continue;
			}

			timescaledb->conn = conn;
			PGresult *res = PQexec(conn, table);

			if (PQresultStatus(res) != PGRES_COMMAND_OK) {
				rc = ts_finish_with_error(conn, cr->rules, i--);
				continue;
			}

			PQclear(res);

			char hypertable[256] = {0};
			snprintf(hypertable, 128,
			    "SELECT create_hypertable('%s', 'timestamp', if_not_exists => TRUE);",
			    cr->rules[i].timescaledb->table);

			res = PQexec(conn, hypertable);
			if (PQresultStatus(res) != PGRES_TUPLES_OK) {
				rc = ts_finish_with_error(conn, cr->rules, i--);
				continue;
			}

			PQclear(res);

		}
	}

	return rc;
}

#endif

#if defined(SUPP_POSTGRESQL)

static int pg_finish_with_error(PGconn *conn, rule *rules, int index)
{
	log_error("Postgresql %s", PQerrorMessage(conn));
	PQfinish(conn);
	rule *r = &rules[index];
	rule_postgresql_free(r->postgresql);
	rule_free(r);
	cvector_erase(rules, index);
	return -1;
}

int
nanomq_client_postgresql(conf_rule *cr, bool init_last)
{
	int      rc = 0;

	char postgresql_table[1024];
	for (int i = 0; i < cvector_size(cr->rules); i++) {
		if (init_last && i != cvector_size(cr->rules) - 1) {
			continue;
		}
		if (RULE_FORWORD_POSTGRESQL == cr->rules[i].forword_type) {
			int  index      = 0;
			char table[256] = { 0 };

			snprintf(table, 128,
			    "CREATE TABLE IF NOT EXISTS %s("
			    "idx SERIAL PRIMARY KEY",
			    cr->rules[i].postgresql->table);

			char *err_msg = NULL;
			bool  first   = true;

			for (; index < 8; index++) {
				if (!cr->rules[i].flag[index])
					continue;

				strcat(table, ", ");
				strcat(table,
				    cr->rules[i].as[index]
				        ? cr->rules[i].as[index]
				        : key_arr[index]);
				strcat(table, type_arr[index]);
			}
			strcat(table, ");");

			rule_postgresql *postgresql = cr->rules[i].postgresql;

			char conninfo[256] = { 0 };
			snprintf(conninfo , 128, "dbname=postgres user=%s password=%s host=%s port=5432", postgresql->username,postgresql->password, postgresql->host);
			PGconn *conn = PQconnectdb(conninfo);

			if (PQstatus(conn) != CONNECTION_OK) {
				rc = pg_finish_with_error(conn, cr->rules, i--);
				continue;
			}

			postgresql->conn = conn;
			PGresult *res = PQexec(conn, table);
			PQclear(res);

			if (PQresultStatus(res) != PGRES_COMMAND_OK) {
				rc = pg_finish_with_error(conn, cr->rules, i--);
				continue;
			}


		}
	}

	return rc;
}

#endif

#if defined(SUPP_MYSQL)
#include <mysql.h>

static int finish_with_error(MYSQL *con, rule *rules, int index)
{
	log_error("%s", mysql_error(con));
	mysql_close(con);
	rule *r = &rules[index];
	rule_mysql_free(r->mysql);
	rule_free(r);
	cvector_erase(rules, index);
	return -1;
}

int
nanomq_client_mysql(conf_rule *cr, bool init_last)
{
	int      rc = 0;

	char *mysql_db = cr->mysql_db
	    ? cr->mysql_db
	    : "mysql_rule_db";

	char mysql_table[1024];
	for (int i = 0; i < cvector_size(cr->rules); i++) {
		if (init_last && i != cvector_size(cr->rules) - 1) {
			continue;
		}
		if (RULE_FORWORD_MYSQL == cr->rules[i].forword_type) {
			int  index      = 0;
			char table[256] = { 0 };

			snprintf(table, 128,
			    "CREATE TABLE IF NOT EXISTS %s("
			    "idx INT PRIMARY KEY AUTO_INCREMENT",
			    cr->rules[i].mysql->table);
			char *err_msg = NULL;
			bool  first   = true;

			for (; index < 8; index++) {
				if (!cr->rules[i].flag[index])
					continue;

				strcat(table, ", ");
				strcat(table,
				    cr->rules[i].as[index]
				        ? cr->rules[i].as[index]
				        : key_arr[index]);
				strcat(table, type_arr[index]);
			}
			strcat(table, ");");

			rule_mysql *mysql = cr->rules[i].mysql;
			MYSQL *con = mysql_init(NULL);
			mysql->conn = con;
			if (con == NULL) {
				rc = finish_with_error(con, cr->rules, i--);
				continue;
			}

			if (mysql_real_connect(con, mysql->host, mysql->username, mysql->password,
			        mysql_db, 0, NULL, 0) == NULL) {
				rc = finish_with_error(con, cr->rules, i--);
				continue;
			}


			if (mysql_query(con, table)) {
				rc = finish_with_error(con, cr->rules, i--);
				continue;
			}

		}
	}

	return rc;
}
#endif


#endif
