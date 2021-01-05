//rewrite by Jaylin EMQ X for MQTT usage
//TODO Independent tcptran protocol 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <mqtt_db.h>

#include "include/nng_debug.h"
#include "core/nng_impl.h"

#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/protocol/mqtt/mqtt.h"


// TCP transport.   Platform specific TCP operations must be
// supplied as well.

typedef struct tcptran_pipe tcptran_pipe;
typedef struct tcptran_ep   tcptran_ep;

// tcp_pipe is one end of a TCP connection.
struct tcptran_pipe {
	nng_stream *    conn;
	nni_pipe *      npipe;	// for statitical
	//uint16_t        peer;		//reserved for MQTT sdk version
	//uint16_t        proto;
	size_t          rcvmax;
	bool            closed;
	nni_list_node   node;
	tcptran_ep *    ep;
	nni_atomic_flag reaped;
	nni_reap_item   reap;
	uint8_t         txlen[NANO_MIN_PACKET_LEN];
	uint8_t         rxlen[NNI_NANO_MAX_PACKET_SIZE];
	size_t          gottxhead;
	size_t          gotrxhead;
	size_t          wanttxhead;
	size_t          wantrxhead;
	nni_list        recvq;
	nni_list        sendq;
	nni_aio *       txaio;
	nni_aio *       rxaio;
	nni_aio *       qsaio;
	nni_aio *       negoaio;
	nni_msg *       rxmsg;
	uint8_t *       conn_buf;
	nni_mtx         mtx;
	conn_param *    tcp_cparam;
	uint8_t			cmd;
	//uint8_t       sli_win[5];	//use aio multiple times instead of seperating 2 packets manually
};

struct tcptran_ep {
	nni_mtx              mtx;
	//uint16_t             proto;
	size_t               rcvmax;
	bool                 fini;
	bool                 started;
	bool                 closed;
	nng_url *            url;
	//const char *         host; // for dialers
	nng_sockaddr         src;
	int                  refcnt; // active pipes
	nni_aio *            useraio;
	nni_aio *            connaio;
	nni_aio *            timeaio;
	nni_list             busypipes; // busy pipes -- ones passed to socket
	nni_list             waitpipes; // pipes waiting to match to socket
	nni_list             negopipes; // pipes busy negotiating
	nni_reap_item        reap;
	//nng_stream_dialer *  dialer;
	nng_stream_listener *listener;
#ifdef NNG_ENABLE_STATS
       nni_stat_item 	     st_rcv_max;
#endif
};

static void tcptran_pipe_send_start(tcptran_pipe *);
static void tcptran_pipe_recv_start(tcptran_pipe *);
static void tcptran_pipe_send_cb(void *);
static void tcptran_pipe_recv_cb(void *);
static void tcptran_pipe_quic_cb(void *arg);
static void tcptran_pipe_nego_cb(void *);
static void tcptran_ep_fini(void *);

static int
tcptran_init(void)
{
	return (0);
}

static void
tcptran_fini(void)
{
}

static void
tcptran_pipe_close(void *arg)
{
	tcptran_pipe *p = arg;

	nni_mtx_lock(&p->mtx);
	p->closed = true;
	nni_mtx_unlock(&p->mtx);

	nni_aio_close(p->rxaio);
	nni_aio_close(p->txaio);
	nni_aio_close(p->qsaio);
	nni_aio_close(p->negoaio);

	nng_stream_close(p->conn);
	debug_syslog("tcptran_pipe_close\n");
}

static void
tcptran_pipe_stop(void *arg)
{
	tcptran_pipe *p = arg;

	nni_aio_stop(p->qsaio);
	nni_aio_stop(p->rxaio);
	nni_aio_stop(p->txaio);
	nni_aio_stop(p->negoaio);
}

static int
tcptran_pipe_init(void *arg, nni_pipe *npipe)
{
    debug_msg("************tcptran_pipe_init************");
	tcptran_pipe *p = arg;
    nni_pipe_set_conn_param(npipe, p->tcp_cparam);
	p->npipe        = npipe;

	return (0);
}

static void
tcptran_pipe_fini(void *arg)
{
	tcptran_pipe *p = arg;
	tcptran_ep *  ep;

	tcptran_pipe_stop(p);
	if ((ep = p->ep) != NULL) {
		nni_mtx_lock(&ep->mtx);
		nni_list_node_remove(&p->node);
		ep->refcnt--;
		if (ep->fini && (ep->refcnt == 0)) {
			nni_reap(&ep->reap, tcptran_ep_fini, ep);
		}
		nni_mtx_unlock(&ep->mtx);
	}

	nni_aio_free(p->qsaio);
	nni_aio_free(p->rxaio);
	nni_aio_free(p->txaio);
	nni_aio_free(p->negoaio);
	nng_stream_free(p->conn);
	nni_msg_free(p->rxmsg);
	nni_mtx_fini(&p->mtx);
	NNI_FREE_STRUCT(p);
}

static void
tcptran_pipe_reap(tcptran_pipe *p)
{
	if (!nni_atomic_flag_test_and_set(&p->reaped)) {
		if (p->conn != NULL) {
			nng_stream_close(p->conn);
		}
		nni_reap(&p->reap, tcptran_pipe_fini, p);
	}
}

static int
tcptran_pipe_alloc(tcptran_pipe **pipep)
{
	tcptran_pipe *p;
	int           rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&p->mtx);
	if (((rv = nni_aio_alloc(&p->txaio, tcptran_pipe_send_cb, p)) != 0) ||
		((rv = nni_aio_alloc(&p->qsaio, tcptran_pipe_quic_cb, p)) != 0) ||
	    ((rv = nni_aio_alloc(&p->rxaio, tcptran_pipe_recv_cb, p)) != 0) ||
	    ((rv = nni_aio_alloc(&p->negoaio, tcptran_pipe_nego_cb, p)) != 0))
	{
		tcptran_pipe_fini(p);
		return (rv);
	}
	nni_aio_list_init(&p->recvq);
	nni_aio_list_init(&p->sendq);
	nni_atomic_flag_reset(&p->reaped);

	*pipep = p;

	return (0);
}

static void
tcptran_ep_match(tcptran_ep *ep)
{
	nni_aio *     aio;
	tcptran_pipe *p;

	if (((aio = ep->useraio) == NULL) ||
	    ((p = nni_list_first(&ep->waitpipes)) == NULL)) {
		return;
	}
	nni_list_remove(&ep->waitpipes, p);
	nni_list_append(&ep->busypipes, p);
	ep->useraio = NULL;
	p->rcvmax   = ep->rcvmax;
	nni_aio_set_output(aio, 0, p);
	nni_aio_finish(aio, 0, 0);
}

/**
 * MQTT protocal negotiate
 * deal with CONNECT packet
 * Fixed header to variable header
 * receive multiple times for complete data packet then reply ACK only once
 * iov_len limits the length readv reads
 * TODO independent with nng SP
 */
static void
tcptran_pipe_nego_cb(void *arg)
{
	tcptran_pipe *p   = arg;
	tcptran_ep *  ep  = p->ep;
	nni_aio *     aio = p->negoaio;
	nni_aio *     uaio;
	uint32_t      len;
	int           rv, len_of_varint=0;

	debug_msg("start tcptran_pipe_nego_cb max len %d pipe_addr %p\n",
		  NANO_CONNECT_PACKET_LEN, p);
	nni_mtx_lock(&ep->mtx);

	if ((rv = nni_aio_result(aio)) != 0) {
		goto error;
	}

	// calculate number of bytes received
	// TODO cannot differ send/receive IO, so skip tx calculation
	// TODO NNG_EMSGSIZE what if received too much garbage ?
	if (p->gotrxhead < p->wantrxhead) {
		p->gotrxhead += nni_aio_count(aio);
	} /*else if (p->gotrxhead >= p->wantrxhead && p->gottxhead >= p->wanttxhead) {
		//Free negopipes again? Dont if cb didnt return when reply ACK/error
		nni_mtx_unlock(&ep->mtx);
		return;
	}*/

	debug_msg("current header : gottx %d gotrx %d needrx %d needtx %d\n",p->gottxhead, p->gotrxhead, p->wantrxhead, p->wanttxhead);
	if (p->gotrxhead >= p->wantrxhead && p->gottxhead < p->wanttxhead) {
		if (p->rxlen[0] != CMD_CONNECT) {
			debug_msg("CMD TYPE %x", p->rxlen[0]);
			rv = NNG_EPROTO;		//in nng error return value must be defined. TODO inject EMQ error enum into NNG? 
			goto error;
		}
		len = get_var_integer(p->rxlen+1, &len_of_varint);
		debug_msg("CMD TYPE %x REMAINING LENGTH %d", p->rxlen[0], len);
		p->wantrxhead = len + 1 + len_of_varint;
	}
	// recv fixed header
	if (p->gotrxhead < EMQ_MAX_FIXED_HEADER_LEN) {
		nni_iov iov;
		iov.iov_len = p->wantrxhead - p->gotrxhead;
		iov.iov_buf = &p->rxlen[p->gotrxhead];
		nni_aio_set_iov(aio, 1, &iov);
		nng_stream_recv(p->conn, aio);
		nni_mtx_unlock(&ep->mtx);
		debug_msg("fixed header : gottx %d gotrx %d needrx %d needtx %d CONNECT Need more bytes msg: str: %s hex: %x %x\n", p->gottxhead, p->gotrxhead, p->wantrxhead, p->wanttxhead, &p->rxlen, p->rxlen[0], p->rxlen[1]);
		return;
	}

	//after fixed header but not receive complete Header. continue receving variable header; in case wantrxhead set less than EMQ_FIXED_HEADER_LEN(BUG)
	if (p->gotrxhead < p->wantrxhead && p->gotrxhead >= EMQ_MAX_FIXED_HEADER_LEN) {
		nni_iov iov;
		iov.iov_len = p->wantrxhead - p->gotrxhead;
		p->conn_buf = nng_alloc(p->wantrxhead);
		memcpy(p->conn_buf, p->rxlen, p->gotrxhead);
		iov.iov_buf = &p->conn_buf[p->gotrxhead];
		nni_aio_set_iov(aio, 1, &iov);
		nng_stream_recv(p->conn, aio);
		nni_mtx_unlock(&ep->mtx);
		debug_msg("variable and payload : gottx %d gotrx %d needrx %d needtx %d hex: %x %x\n", p->gottxhead, p->gotrxhead, p->wantrxhead, p->wanttxhead, p->rxlen[0], p->rxlen[1]);
		return;
	}

	// We have both sent and received the CONNECT headers.  Lets check TODO CONNECT packet serialization
	debug_msg("******** %d %d %d %d nego msg: %s ----- %x\n",p->gottxhead, p->gotrxhead, p->wantrxhead, p->wanttxhead, p->rxlen, p->rxlen[0]);

	//reply error/CONNECT ACK
	if (p->gottxhead < p->wanttxhead && p->gotrxhead >= p->wantrxhead) {
		nni_iov iov;
		p->tcp_cparam = nng_alloc(sizeof(struct conn_param));
		if (conn_handler(p->conn_buf, p->tcp_cparam) > 0) {
			nng_free(p->conn_buf, p->wantrxhead);
			if (p->tcp_cparam->pro_ver == PROTOCOL_VERSION_v5) {
				p->wanttxhead += 1;
				// p->gottxhead += 1;
				p->txlen[1] = 3; // setting remainlen
				p->txlen[4] = 0x00; // property len
			}
			iov.iov_len = p->wanttxhead - p->gottxhead;
			iov.iov_buf = &p->txlen[p->gottxhead];
			debug_msg("[%ld] body [%x %x %x %x %x]", iov.iov_len,
					  p->txlen[0], p->txlen[1], p->txlen[2], p->txlen[3], p->txlen[4]);
			// send it down...
			nni_aio_set_iov(aio, 1, &iov);
			nng_stream_send(p->conn, aio);
			debug_msg("tcptran_pipe_nego_cb: reply ACK\n");
			p->gottxhead = p->wanttxhead;
			nni_mtx_unlock(&ep->mtx);
			return;
		} else {
			debug_msg("%d", rv);
			rv = NNG_EPROTO;
			goto error;
		}
	}

	//TODO:  define what version of MQTT
	//NNI_GET16(&p->rxlen[4], p->peer);

	// We are all ready now.  We put this in the wait list, and
	// then try to run the matcher.
	nni_list_remove(&ep->negopipes, p);
	nni_list_append(&ep->waitpipes, p);

	tcptran_ep_match(ep);
	nni_mtx_unlock(&ep->mtx);
	debug_msg("^^^^^^^^^^^^^^end of tcptran_pipe_nego_cb^^^^^^^^^^^^^^^^^^^^\n");
	return;

error:
	nng_stream_close(p->conn);

	if ((uaio = ep->useraio) != NULL) {
		ep->useraio = NULL;
		nni_aio_finish_error(uaio, rv);
	}
	nni_mtx_unlock(&ep->mtx);
	tcptran_pipe_reap(p);
	debug_msg("connect nego error rv: %d!", rv);
	return;
}

static void
tcptran_pipe_quic_cb(void *arg)
{
	return;
}

static void
tcptran_pipe_send_cb(void *arg)
{
	tcptran_pipe *p = arg;
	int           rv;
	nni_aio *     aio;
	size_t        n;
	nni_msg *     msg;
	nni_aio *     txaio = p->txaio;

	nni_mtx_lock(&p->mtx);
	aio = nni_list_first(&p->sendq);

	debug_msg("############### tcptran_pipe_send_cb ################");

	if ((rv = nni_aio_result(txaio)) != 0) {
		nni_pipe_bump_error(p->npipe, rv);
		nni_aio_list_remove(aio);
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	n = nni_aio_count(txaio);
	nni_aio_iov_advance(txaio, n);
	debug_msg("tcp socket sent %d bytes iov %d", n, nni_aio_iov_count(txaio));

	if (nni_aio_iov_count(txaio) > 0) {
		nng_stream_send(p->conn, txaio);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	nni_aio_list_remove(aio);
	tcptran_pipe_send_start(p);

	msg = nni_aio_get_msg(aio);
	n   = nni_msg_len(msg);
	nni_pipe_bump_tx(p->npipe, n);
	nni_mtx_unlock(&p->mtx);

	nni_aio_set_msg(aio, NULL);
	nni_msg_free(msg);
	nni_aio_finish_sync(aio, 0, n);
}

/*
 * deal with MQTT protocol
 * insure read complete MQTT packet from socket
 */
static void
tcptran_pipe_recv_cb(void *arg)
{
	uint8_t *     variable_ptr = NULL, * payload_ptr = NULL;
	//uint8_t *     header_ptr;
	nni_aio *     aio;
	nni_iov       iov;
	uint8_t	      type;
	//uint16_t      fixed_header;
	uint32_t      len = 0, rv, pos = 1;
	size_t        n;
	nni_msg *     msg;
	tcptran_pipe* p = arg;
	nni_aio *     rxaio = p->rxaio;
	nni_aio *     txaio = p->txaio;
	nni_aio *     qsaio = p->qsaio;
	conn_param *  cparam;

	debug_msg("tcptran_pipe_recv_cb %p\n", p);
	nni_mtx_lock(&p->mtx);

	aio = nni_list_first(&p->recvq);

	if ((rv = nni_aio_result(rxaio)) != 0) {
		debug_msg("nni aio error!! %d\n", rv);
		goto recv_error;
	}

	n = nni_aio_count(rxaio);
	p->gotrxhead += n;

	nni_aio_iov_advance(rxaio, n);
	//not receive enough bytes, deal with remaining length
	len = get_var_integer(p->rxlen, &pos);
	debug_msg("new %d recevied %d header %x %d pos: %d len : %d",
		  n, p->gotrxhead,p->rxlen[0], p->rxlen[1], pos, len);
	debug_msg("still need byte count:%d > 0\n", nni_aio_iov_count(rxaio));

	if (nni_aio_iov_count(rxaio) > 0) {
		debug_msg("got: %x %x, %d!!\n", p->rxlen[0],p->rxlen[1], strlen(p->rxlen));
		nng_stream_recv(p->conn, rxaio);
		nni_mtx_unlock(&p->mtx);
		return;
	} else if (p->rxlen[p->gotrxhead - 1] > 0x7f && p->gotrxhead <= EMQ_MAX_FIXED_HEADER_LEN) {
		//length error
		if (p->gotrxhead == EMQ_MAX_FIXED_HEADER_LEN) {
			rv = NNG_EMSGSIZE;
			goto recv_error;
		}
		//same packet
		iov.iov_buf = &p->rxlen[p->gotrxhead];
		iov.iov_len = 1;
		nni_aio_set_iov(rxaio, 1, &iov);
		nng_stream_recv(p->conn, rxaio);
		nni_mtx_unlock(&p->mtx);
		return;
	} else if (len == 0 && n == 2) {
		if ((p->rxlen[0]&0XFF) == CMD_PINGREQ) {
			p->txlen[0] = CMD_PINGRESP;
			p->txlen[1] = 0x00;
			iov.iov_len = 2;
			iov.iov_buf = &p->txlen;
			// send it down...
			nni_aio_set_iov(qsaio, 1, &iov);
			p->cmd = CMD_PINGRESP;
			nng_stream_send(p->conn, qsaio);
		} else if ((p->rxlen[0]&0XFF) == CMD_DISCONNECT) {
		}
	}

	//finish fixed header
	p->wantrxhead = len + p->gotrxhead;
	cparam = p->tcp_cparam;

	if (p->rxmsg == NULL) {
		// We should have gotten a message header. len -> remaining length to define how many bytes left
		//NNI_GET64(p->rxlen, len);	
		//p->remain_len = len;
		debug_msg("pipe %p header got: %x %x %x %x %x, %ld!!\n",
			      p, p->rxlen[0],p->rxlen[1], p->rxlen[2], p->rxlen[3], p->rxlen[4], p->wantrxhead);
		// Make sure the message payload is not too big.  If it is
		// the caller will shut down the pipe.
		if ((len > p->rcvmax) && (p->rcvmax > 0)) {
			debug_msg("size error\n");
			rv = NNG_EMSGSIZE;
			goto recv_error;
		}

		if ((rv = nni_msg_alloc(&p->rxmsg, (size_t) len)) != 0) {
			debug_msg("mem error %ld\n", (size_t)len);
			goto recv_error;
		}

		// Submit the rest of the data for a read -- seperate Fixed header with variable header and so on
		//  we want to read the entire message now.
		if (len != 0) {
			iov.iov_buf = nni_msg_body(p->rxmsg);
			iov.iov_len = len;

			nni_aio_set_iov(rxaio, 1, &iov);
			debug_msg("second recv action+++++++++++");
			nng_stream_recv(p->conn, rxaio);
			nni_mtx_unlock(&p->mtx);
			return;
		}
	}

	// solve the error due to out of p->rcvmax ? if so, cancel the size_error above
	if (len > nni_msg_len(p->rxmsg)) {
		if ((rv = nni_msg_realloc(p->rxmsg, (size_t) len)) != 0) {
			debug_msg("mem error %ld\n", (size_t)len);
			goto recv_error;
		}

		// Submit the rest of the data for a read -- seperate Fixed header with variable header and so on
		//  we want to read the entire message now.
		iov.iov_buf = nni_msg_body(p->rxmsg);
		iov.iov_len = len;

		nni_aio_set_iov(rxaio, 1, &iov);
		debug_msg("second recv action+++++++++++");
		nng_stream_recv(p->conn, rxaio);
		nni_mtx_unlock(&p->mtx);
		return;
	}

	//TODO reply ACK?

	// We read a message completely.  Let the user know the good news. use as application message callback of users
	nni_aio_list_remove(aio);		//need this to align with nng 
	msg      = p->rxmsg;
	p->rxmsg = NULL;
	n        = nni_msg_len(msg);
	type	 = p->rxlen[0]&0xf0;

	fixed_header_adaptor(p->rxlen, msg);
//	cparam = (conn_param *)nng_alloc(sizeof(struct conn_param));
//	copy_conn_param(cparam, &p->tcp_cparam);
	nni_msg_set_conn_param(msg, cparam);
	nni_msg_set_remaining_len(msg, len);
	nni_msg_set_cmd_type(msg, type);
	debug_msg("remain_len %d cparam %p clientid %s username %s proto %d\n", len, cparam, &cparam->clientid.body, &cparam->username.body, cparam->pro_ver);
	//header_ptr = nni_msg_header(msg);
	variable_ptr = nni_msg_variable_ptr(msg);
	uint32_t len_of_varint = 0;

	// set the payload pointer of msg according to packet_type
	debug_msg("The type of msg is %x", type);
	if(type == CMD_SUBSCRIBE){
		if (cparam->pro_ver == PROTOCOL_VERSION_v5) {
			len_of_varint = 0;
			len = get_var_integer(variable_ptr + 2, &len_of_varint);
			payload_ptr = variable_ptr + 2 + len + len_of_varint;
		} else {
			payload_ptr = variable_ptr + 2;
		}
	}else if(type == CMD_UNSUBSCRIBE) {
		if (cparam->pro_ver == PROTOCOL_VERSION_v5) {
			len_of_varint = 0;
			len = get_var_integer(variable_ptr + 2, &len_of_varint);
			payload_ptr = variable_ptr + 2 + len + len_of_varint;
		} else {
			payload_ptr = variable_ptr + 2;
		}
	}else if(type == CMD_PUBLISH){
		uint8_t qos_pac;
		uint16_t pid;
		qos_pac = nni_msg_get_pub_qos(msg);
		if (qos_pac > 0) {
			if (qos_pac == 1) {
				p->txlen[0] = CMD_PUBACK;
			} else if (qos_pac == 2) {
				p->txlen[0] = CMD_PUBREC;
			}
				p->txlen[1] = 0x02;
				pid = nni_msg_get_pub_pid(msg);
				NNI_PUT16(p->txlen + 2, pid);
				iov.iov_len = 4;
				iov.iov_buf = &p->txlen;
				// send it down...
				nni_aio_set_iov(qsaio, 1, &iov);

				p->cmd = CMD_PUBREC;
				nng_stream_send(p->conn, qsaio);	
		}
	} else if (type == CMD_PUBREC){
		uint8_t *tmp;
		p->txlen[0] = 0X62;
		p->txlen[1] = 0x02;
		tmp = nni_msg_body(msg);
		memcpy(p->txlen + 2, tmp, 2);
		iov.iov_len = 4;
		iov.iov_buf = &p->txlen;
		// send it down...
		nni_aio_set_iov(qsaio, 1, &iov);
		p->cmd = CMD_PUBREL;
		nng_stream_send(p->conn, qsaio);
	}else if (type == CMD_PUBREL){
		uint8_t *tmp;
		p->txlen[0] = CMD_PUBCOMP;
		p->txlen[1] = 0x02;
		tmp = nni_msg_body(msg);
		memcpy(p->txlen + 2, tmp, 2);
		iov.iov_len = 4;
		iov.iov_buf = &p->txlen;
		// send it down...
		nni_aio_set_iov(qsaio, 1, &iov);
		p->cmd = CMD_PUBCOMP;
		nng_stream_send(p->conn, qsaio);
	}else{
		payload_ptr = NULL;
	}
	nni_msg_set_payload_ptr(msg, payload_ptr);

	//keep connection & Schedule next receive
	nni_pipe_bump_rx(p->npipe, n);
	tcptran_pipe_recv_start(p);
	nni_mtx_unlock(&p->mtx);

	nni_aio_set_msg(aio, msg);
	nni_aio_finish_sync(aio, 0, n);
	debug_msg("end of tcptran_pipe_recv_cb: synch! %p\n", p);
	return;

recv_error:
	nni_aio_list_remove(aio);
	msg      = p->rxmsg;
	p->rxmsg = NULL;
	nni_pipe_bump_error(p->npipe, rv);
	nni_mtx_unlock(&p->mtx);

	nni_msg_free(msg);
	nni_aio_finish_error(aio, rv);
	debug_msg("tcptran_pipe_recv_cb: recv error rv: %d\n", rv);
	return;
quit:
	nni_aio_list_remove(aio);
	nni_list_append(&p->sendq, aio);
	//simply quit after reply PINGRESP to clinet
	tcptran_pipe_recv_start(p);
	nni_mtx_unlock(&p->mtx);
	return;
}

static void
tcptran_pipe_send_cancel(nni_aio *aio, void *arg, int rv)
{
	tcptran_pipe *p = arg;

	nni_mtx_lock(&p->mtx);
	if (!nni_aio_list_active(aio)) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	// If this is being sent, then cancel the pending transfer.
	// The callback on the txaio will cause the user aio to
	// be canceled too.
	if (nni_list_first(&p->sendq) == aio) {
		nni_aio_abort(p->txaio, rv);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	nni_aio_list_remove(aio);
	nni_mtx_unlock(&p->mtx);

	nni_aio_finish_error(aio, rv);
}

static void
tcptran_pipe_send_start(tcptran_pipe *p)
{
	nni_aio *aio;
	nni_aio *txaio;
	nni_msg *msg;
	int      niov;
	nni_iov  iov[3];
	//uint8_t	*pos;
	//uint16_t pid;
	//uint64_t len;

	debug_msg("########### tcptran_pipe_send_start ###########");
	if (p->closed) {
		while ((aio = nni_list_first(&p->sendq)) != NULL) {
			nni_list_remove(&p->sendq, aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
		return;
	}

	if ((aio = nni_list_first(&p->sendq)) == NULL) {
		debug_msg("aio not functioning");
		return;
	}

	// This runs to send the message.
	msg = nni_aio_get_msg(aio);
	//len = nni_msg_len(msg) + nni_msg_header_len(msg);
	//NNI_PUT64(p->txlen, len);

	txaio          = p->txaio;
	niov           = 0;
	//iov[0].iov_buf = p->txlen;
	//iov[0].iov_len = sizeof(p->txlen);
	//niov++;
	// if (nni_msg_cmd_type(msg) == CMD_PUBREL) {
	// 	pos = nni_msg_header(msg);
	// 	pid = nni_pipe_inc_packetid(p->npipe);
	// 	memcpy(pos + 2, &pid, 2);
	// }
	if (nni_msg_header_len(msg) > 0) {
		iov[niov].iov_buf = nni_msg_header(msg);
		iov[niov].iov_len = nni_msg_header_len(msg);
		niov++;
	}
	if (nni_msg_len(msg) > 0) {
		iov[niov].iov_buf = nni_msg_body(msg);
		iov[niov].iov_len = nni_msg_len(msg);
		niov++;
	}
	nni_aio_set_iov(txaio, niov, iov);
	nng_stream_send(p->conn, txaio);
}

static void
tcptran_pipe_send(void *arg, nni_aio *aio)
{
	tcptran_pipe *p = arg;
	int           rv;

	debug_msg("####################tcptran_pipe_send###########");
	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, tcptran_pipe_send_cancel, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&p->sendq, aio);
	if (nni_list_first(&p->sendq) == aio) {
		tcptran_pipe_send_start(p);
	}
	nni_mtx_unlock(&p->mtx);
}

static void
tcptran_pipe_recv_cancel(nni_aio *aio, void *arg, int rv)
{
	tcptran_pipe *p = arg;

	nni_mtx_lock(&p->mtx);
	if (!nni_aio_list_active(aio)) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	// If receive in progress, then cancel the pending transfer.
	// The callback on the rxaio will cause the user aio to
	// be canceled too.
	if (nni_list_first(&p->recvq) == aio) {
		nni_aio_abort(p->rxaio, rv);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	nni_aio_list_remove(aio);
	nni_mtx_unlock(&p->mtx);
	nni_aio_finish_error(aio, rv);
}

static void
tcptran_pipe_recv_start(tcptran_pipe *p)
{
	nni_aio *rxaio;
	nni_iov  iov;
	debug_msg("second oder! tcptran_pipe_recv_start\n");
	NNI_ASSERT(p->rxmsg == NULL);

	if (p->closed) {
		nni_aio *aio;
		while ((aio = nni_list_first(&p->recvq)) != NULL) {
			nni_list_remove(&p->recvq, aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
		return;
	}
	if (nni_list_empty(&p->recvq)) {
		return;
	}

	// Schedule a read of the fixed header.
	rxaio       = p->rxaio;
	p->gotrxhead  = 0;
	p->gottxhead  = 0;
	p->wantrxhead = EMQ_MIN_FIXED_HEADER_LEN;
	p->wanttxhead = 0;
	//p->remain_len = 0;
	iov.iov_buf = p->rxlen;
	iov.iov_len = EMQ_MIN_FIXED_HEADER_LEN;
	nni_aio_set_iov(rxaio, 1, &iov);
	nng_stream_recv(p->conn, rxaio);
}

static void
tcptran_pipe_recv(void *arg, nni_aio *aio)
{
	tcptran_pipe *p = arg;
	int           rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, tcptran_pipe_recv_cancel, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	if (nni_aio_list_active(aio) == 0) {
	  nni_list_append(&p->recvq, aio);
	}

	if (nni_list_first(&p->recvq) == aio) {
		tcptran_pipe_recv_start(p);
	}
	nni_mtx_unlock(&p->mtx);
}

/*
static uint16_t
tcptran_pipe_peer(void *arg)
{
	tcptran_pipe *p = arg;

	return (p->peer);
}
*/

static int
tcptran_pipe_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	tcptran_pipe *p = arg;
	return (nni_stream_getx(p->conn, name, buf, szp, t));
}

//DEAL WITH CONNECT when PIPE INIT
static void
tcptran_pipe_start(tcptran_pipe *p, nng_stream *conn, tcptran_ep *ep)
{
	nni_iov iov;
	//nni_tcp_conn *c;

	ep->refcnt++;

	p->conn  = conn;
	p->ep    = ep;
	//p->proto = ep->proto;

	p->txlen[0] = CMD_CONNACK;
	p->txlen[1] = 0x02;
	p->txlen[2] = 0;
	p->txlen[3] = 0;

	debug_msg("tcptran_pipe_start!");
	//TODO abide with CONNECT header
	p->gotrxhead  = 0;
	p->gottxhead  = 0;
	p->wantrxhead = NANO_CONNECT_PACKET_LEN;		//packet type 1 + remaining length 1 + protocal name 7 + flag 1 + keepalive 2 = 12
	p->wanttxhead = 4;
	iov.iov_len   = EMQ_MIN_HEADER_LEN;	//dynamic
	iov.iov_buf   = &p->txlen[0];

	nni_aio_set_iov(p->negoaio, 1, &iov);			//maybe not necessary? delete?
	nni_list_append(&ep->negopipes, p);

	//reply to client immediately if needed otherwise just trigger next IO
	//nng_stream_send(p->conn, p->negoaio);

	nni_aio_set_timeout(p->negoaio, 15000); // 15 sec timeout to negotiate abide with emqx
	nni_aio_finish(p->negoaio, 0, 0);
}

static void
tcptran_ep_fini(void *arg)
{
	tcptran_ep *ep = arg;

	nni_mtx_lock(&ep->mtx);
	ep->fini = true;
	if (ep->refcnt != 0) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	nni_mtx_unlock(&ep->mtx);
	nni_aio_stop(ep->timeaio);
	nni_aio_stop(ep->connaio);
	//nng_stream_dialer_free(ep->dialer);
	nng_stream_listener_free(ep->listener);
	nni_aio_free(ep->timeaio);
	nni_aio_free(ep->connaio);

	nni_mtx_fini(&ep->mtx);
	NNI_FREE_STRUCT(ep);
}

static void
tcptran_ep_close(void *arg)
{
	tcptran_ep *  ep = arg;
	tcptran_pipe *p;

	nni_mtx_lock(&ep->mtx);

	debug_syslog("tcptran_ep_close");
	ep->closed = true;
	nni_aio_close(ep->timeaio);
	if (ep->listener != NULL) {
		nng_stream_listener_close(ep->listener);
	}
	NNI_LIST_FOREACH (&ep->negopipes, p) {
		tcptran_pipe_close(p);
	}
	NNI_LIST_FOREACH (&ep->waitpipes, p) {
		tcptran_pipe_close(p);
	}
	NNI_LIST_FOREACH (&ep->busypipes, p) {
		tcptran_pipe_close(p);
	}
	if (ep->useraio != NULL) {
		nni_aio_finish_error(ep->useraio, NNG_ECLOSED);
		ep->useraio = NULL;
	}

	nni_mtx_unlock(&ep->mtx);
}

// This parses off the optional source address that this transport uses.
// The special handling of this URL format is quite honestly an historical
// mistake, which we would remove if we could.static int
tcptran_url_parse_source(nng_url *url, nng_sockaddr *sa, const nng_url *surl)
{
	int      af;
	char *   semi;
	char *   src;
	size_t   len;
	int      rv;
	nni_aio *aio;

	// We modify the URL.  This relies on the fact that the underlying
	// transport does not free this, so we can just use references.

	url->u_scheme   = surl->u_scheme;
	url->u_port     = surl->u_port;
	url->u_hostname = surl->u_hostname;

	if ((semi = strchr(url->u_hostname, ';')) == NULL) {
		memset(sa, 0, sizeof(*sa));
		return (0);
	}

	len             = (size_t)(semi - url->u_hostname);
	url->u_hostname = semi + 1;

	if (strcmp(surl->u_scheme, "tcp") == 0) {
		af = NNG_AF_UNSPEC;
	} else if (strcmp(surl->u_scheme, "tcp4") == 0) {
		af = NNG_AF_INET;
	} else if (strcmp(surl->u_scheme, "tcp6") == 0) {
		af = NNG_AF_INET6;
	} else {
		return (NNG_EADDRINVAL);
	}

	if ((src = nni_alloc(len + 1)) == NULL) {
		return (NNG_ENOMEM);
	}
	memcpy(src, surl->u_hostname, len);
	src[len] = '\0';

	if ((rv = nni_aio_alloc(&aio, NULL, NULL)) != 0) {
		nni_free(src, len + 1);
		return (rv);
	}

	nni_resolv_ip(src, "0", af, true, sa, aio);
	nni_aio_wait(aio);
	nni_aio_free(aio);
	nni_free(src, len + 1);
	return (rv);
}

static void
tcptran_timer_cb(void *arg)
{
	tcptran_ep *ep = arg;
	if (nni_aio_result(ep->timeaio) == 0) {
		nng_stream_listener_accept(ep->listener, ep->connaio);
	}
}

// TCP accpet trigger
static void
tcptran_accept_cb(void *arg)
{
	tcptran_ep *  ep  = arg;
	nni_aio *     aio = ep->connaio;
	tcptran_pipe *p;
	int           rv;
	nng_stream *  conn;

	nni_mtx_lock(&ep->mtx);

	if ((rv = nni_aio_result(aio)) != 0) {
		goto error;
	}

	conn = nni_aio_get_output(aio, 0);
	if ((rv = tcptran_pipe_alloc(&p)) != 0) {
		nng_stream_free(conn);
		goto error;
	}

	if (ep->closed) {
		tcptran_pipe_fini(p);
		nng_stream_free(conn);
		rv = NNG_ECLOSED;
		goto error;
	}
	tcptran_pipe_start(p, conn, ep);
	nng_stream_listener_accept(ep->listener, ep->connaio);
	nni_mtx_unlock(&ep->mtx);
	return;

error:
	// When an error here occurs, let's send a notice up to the consumer.
	// That way it can be reported properly.
	if ((aio = ep->useraio) != NULL) {
		ep->useraio = NULL;
		nni_aio_finish_error(aio, rv);
	}
	switch (rv) {

	case NNG_ENOMEM:
	case NNG_ENOFILES:
		nng_sleep_aio(10, ep->timeaio);
		break;

	default:
		if (!ep->closed) {
			nng_stream_listener_accept(ep->listener, ep->connaio);
		}
		break;
	}
	nni_mtx_unlock(&ep->mtx);
}
//abandoned
static void
tcptran_dial_cb(void *arg)
{
	return;
}

static int
tcptran_ep_init(tcptran_ep **epp, nng_url *url, nni_sock *sock)
{
	tcptran_ep *ep;

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&ep->mtx);
	NNI_LIST_INIT(&ep->busypipes, tcptran_pipe, node);
	NNI_LIST_INIT(&ep->waitpipes, tcptran_pipe, node);
	NNI_LIST_INIT(&ep->negopipes, tcptran_pipe, node);

	//ep->proto = nni_sock_proto_id(sock);
	ep->url   = url;
#ifdef NNG_ENABLE_STATS
        static const nni_stat_info rcv_max_info = {
            .si_name   = "rcv_max",
            .si_desc   = "maximum receive size",
            .si_type   = NNG_STAT_LEVEL,
            .si_unit   = NNG_UNIT_BYTES,
            .si_atomic = true,
        };
        nni_stat_init(&ep->st_rcv_max, &rcv_max_info);
#endif

	*epp = ep;
	return (0);
}

static int
tcptran_dialer_init(void **dp, nng_url *url, nni_dialer *ndialer)
{
	debug_msg("tcptran_dialer_init");
	return (0);
}

static int
tcptran_listener_init(void **lp, nng_url *url, nni_listener *nlistener)
{
	tcptran_ep *ep;
	int         rv;
	nni_sock *  sock = nni_listener_sock(nlistener);

	// Check for invalid URL components.
	if ((strlen(url->u_path) != 0) && (strcmp(url->u_path, "/") != 0)) {
		return (NNG_EADDRINVAL);
	}
	if ((url->u_fragment != NULL) || (url->u_userinfo != NULL) ||
	    (url->u_query != NULL)) {
		return (NNG_EADDRINVAL);
	}

	if ((rv = tcptran_ep_init(&ep, url, sock)) != 0) {
		return (rv);
	}

	if (((rv = nni_aio_alloc(&ep->connaio, tcptran_accept_cb, ep)) != 0) ||
	    ((rv = nni_aio_alloc(&ep->timeaio, tcptran_timer_cb, ep)) != 0) ||
	    ((rv = nng_stream_listener_alloc_url(&ep->listener, url)) != 0)) {
		tcptran_ep_fini(ep);
		return (rv);
	}

#ifdef NNG_ENABLE_STATS
        nni_listener_add_stat(nlistener, &ep->st_rcv_max);
#endif
	*lp = ep;
	return (0);
}

static void
tcptran_ep_cancel(nni_aio *aio, void *arg, int rv)
{
	tcptran_ep *ep = arg;
	nni_mtx_lock(&ep->mtx);
	if (ep->useraio == aio) {
		ep->useraio = NULL;
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&ep->mtx);
}

static void
tcptran_ep_connect(void *arg, nni_aio *aio)
{
	debug_msg("tcptran_ep_connect ");
}

//TODO network interface bind
static int
tcptran_ep_get_url(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tcptran_ep *ep = arg;
	char *      s;
	int         rv;
	int         port = 0;

	if (ep->listener != NULL) {
		(void) nng_stream_listener_get_int(
		    ep->listener, NNG_OPT_TCP_BOUND_PORT, &port);
	}

	if ((rv = nni_url_asprintf_port(&s, ep->url, port)) == 0) {
		rv = nni_copyout_str(s, v, szp, t);
		nni_strfree(s);
	}
	return (rv);
}

static int
tcptran_ep_get_recvmaxsz(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tcptran_ep *ep = arg;
	int         rv;

	nni_mtx_lock(&ep->mtx);
	rv = nni_copyout_size(ep->rcvmax, v, szp, t);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static int
tcptran_ep_set_recvmaxsz(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tcptran_ep *ep = arg;
	size_t      val;
	int         rv;
	if ((rv = nni_copyin_size(&val, v, sz, 0, NNI_MAXSZ, t)) == 0) {
		tcptran_pipe *p;
		nni_mtx_lock(&ep->mtx);
		ep->rcvmax = val;
		NNI_LIST_FOREACH (&ep->waitpipes, p) {
			p->rcvmax = val;
		}
		NNI_LIST_FOREACH (&ep->negopipes, p) {
			p->rcvmax = val;
		}
		NNI_LIST_FOREACH (&ep->busypipes, p) {
			p->rcvmax = val;
		}
		nni_mtx_unlock(&ep->mtx);
#ifdef NNG_ENABLE_STATS
		nni_stat_set_value(&ep->st_rcv_max, val);
#endif  
	}
	return (rv);
}

static int
tcptran_ep_bind(void *arg)
{
	tcptran_ep *ep = arg;
	int         rv;

	nni_mtx_lock(&ep->mtx);
	rv = nng_stream_listener_listen(ep->listener);
	nni_mtx_unlock(&ep->mtx);

	return (rv);
}

static void
tcptran_ep_accept(void *arg, nni_aio *aio)
{
	tcptran_ep *ep = arg;
	int         rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&ep->mtx);
	if (ep->closed) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if (ep->useraio != NULL) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, NNG_EBUSY);
		return;
	}
	if ((rv = nni_aio_schedule(aio, tcptran_ep_cancel, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	ep->useraio = aio;
	if (!ep->started) {
		ep->started = true;
		nng_stream_listener_accept(ep->listener, ep->connaio);
	} else {
		tcptran_ep_match(ep);
	}
	nni_mtx_unlock(&ep->mtx);
}

static nni_tran_pipe_ops tcptran_pipe_ops = {
	.p_init   = tcptran_pipe_init,
	.p_fini   = tcptran_pipe_fini,
	.p_stop   = tcptran_pipe_stop,
	.p_send   = tcptran_pipe_send,
	.p_recv   = tcptran_pipe_recv,
	.p_close  = tcptran_pipe_close,
	//.p_peer   = tcptran_pipe_peer,
	.p_getopt = tcptran_pipe_getopt,
};

static const nni_option tcptran_ep_opts[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ,
	    .o_get  = tcptran_ep_get_recvmaxsz,
	    .o_set  = tcptran_ep_set_recvmaxsz,
	},
	{
	    .o_name = NNG_OPT_URL,
	    .o_get  = tcptran_ep_get_url,
	},
	// terminate list
	{
	    .o_name = NULL,
	},
};

static int
tcptran_dialer_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	return 0;
}

static int
tcptran_dialer_setopt(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	return 0;
}

static int
tcptran_listener_getopt(
    void *arg, const char *name, void *buf, size_t *szp, nni_type t)
{
	tcptran_ep *ep = arg;
	int         rv;

	rv = nni_stream_listener_getx(ep->listener, name, buf, szp, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_getopt(tcptran_ep_opts, name, ep, buf, szp, t);
	}
	return (rv);
}

static int
tcptran_listener_setopt(
    void *arg, const char *name, const void *buf, size_t sz, nni_type t)
{
	tcptran_ep *ep = arg;
	int         rv;

	rv = nni_stream_listener_setx(ep->listener, name, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_setopt(tcptran_ep_opts, name, ep, buf, sz, t);
	}
	return (rv);
}

static int
tcptran_check_recvmaxsz(const void *v, size_t sz, nni_type t)
{
	return (nni_copyin_size(NULL, v, sz, 0, NNI_MAXSZ, t));
}

static nni_chkoption tcptran_checkopts[] = {
	{
	    .o_name  = NNG_OPT_RECVMAXSZ,
	    .o_check = tcptran_check_recvmaxsz,
	},
	{
	    .o_name = NULL,
	},
};

static int
tcptran_checkopt(const char *name, const void *buf, size_t sz, nni_type t)
{
	int rv;
	rv = nni_chkopt(tcptran_checkopts, name, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_stream_checkopt("tcp", name, buf, sz, t);
	}
	return (rv);
}

static nni_tran_dialer_ops tcptran_dialer_ops = {
/*	.d_init    = tcptran_dialer_init,
	.d_fini    = tcptran_ep_fini,
	.d_connect = tcptran_ep_connect,
	.d_close   = tcptran_ep_close,
	.d_getopt  = tcptran_dialer_getopt,
	.d_setopt  = tcptran_dialer_setopt,*/
};

static nni_tran_listener_ops tcptran_listener_ops = {
	.l_init   = tcptran_listener_init,
	.l_fini   = tcptran_ep_fini,
	.l_bind   = tcptran_ep_bind,
	.l_accept = tcptran_ep_accept,
	.l_close  = tcptran_ep_close,
	.l_getopt = tcptran_listener_getopt,
	.l_setopt = tcptran_listener_setopt,
};

static nni_tran tcp_tran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "tcp",
	.tran_dialer   = &tcptran_dialer_ops,
	.tran_listener = &tcptran_listener_ops,
	.tran_pipe     = &tcptran_pipe_ops,
	.tran_init     = tcptran_init,
	.tran_fini     = tcptran_fini,
	.tran_checkopt = tcptran_checkopt,
};

static nni_tran tcp4_tran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "tcp4",
	.tran_dialer   = &tcptran_dialer_ops,
	.tran_listener = &tcptran_listener_ops,
	.tran_pipe     = &tcptran_pipe_ops,
	.tran_init     = tcptran_init,
	.tran_fini     = tcptran_fini,
	.tran_checkopt = tcptran_checkopt,
};

/**
 * TODO compatible with nng and mqtt
 * 
static nni_tran tcp4_tran_nanomq = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "tcp4",
	.tran_dialer   = &tcptran_dialer_ops,
	.tran_listener = &tcptran_listener_ops,
	.tran_pipe     = &tcptran_pipe_ops,
	.tran_init     = tcptran_init,
	.tran_fini     = tcptran_fini,
	.tran_checkopt = tcptran_checkopt,
};
 * 
 */

static nni_tran tcp6_tran = {
	.tran_version  = NNI_TRANSPORT_VERSION,
	.tran_scheme   = "tcp6",
	.tran_dialer   = &tcptran_dialer_ops,
	.tran_listener = &tcptran_listener_ops,
	.tran_pipe     = &tcptran_pipe_ops,
	.tran_init     = tcptran_init,
	.tran_fini     = tcptran_fini,
	.tran_checkopt = tcptran_checkopt,
};

int
nng_tcp_register(void)
{
	int rv;
	if (((rv = nni_tran_register(&tcp_tran)) != 0) ||
	    ((rv = nni_tran_register(&tcp4_tran)) != 0) ||
	    ((rv = nni_tran_register(&tcp6_tran)) != 0)) {
		return (rv);
	}
	return (0);
}
