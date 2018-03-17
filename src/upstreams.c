/*
 * Copyright (c) 2018, NLNet Labs, Sinodun
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * * Neither the names of the copyright holders nor the
 *   names of its contributors may be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Verisign, Inc. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "upstreams.h"
#include "context.h"
#include "util-internal.h"
#include "platform.h"
#include "debug.h"
#include "general.h"
#include "gldns/rrdef.h"

#ifndef USE_WINSOCK
#include <netdb.h>
#else
#include <iphlpapi.h>
typedef unsigned short in_port_t;
#endif


#define STUB_TRY_AGAIN_LATER   -24 /* EMFILE, i.e. Out of OS resources */
#define STUB_TRY_NEXT_UPSTREAM -126

uint64_t
_getdns_get_time_as_uintt64() {

	struct timeval tv;
	uint64_t       now;

	if (gettimeofday(&tv, NULL)) {
		return 0;
	}
	now = tv.tv_sec * 1000000 + tv.tv_usec;
	return now;
}

getdns_return_t
_getdns_submit_stub_request(getdns_network_req *netreq, uint64_t *now_ms);

static void _fallback_resubmit_netreq(getdns_network_req *netreq, uint64_t *now_ms)
{
	DEBUG_STUB("%s %-35s: MSG: %p TYPE: %d\n", STUB_DEBUG_ENTRY, __FUNC__,
	           (void*)netreq, netreq->request_type);

	if (_getdns_submit_stub_request(netreq, now_ms) == GETDNS_RETURN_GOOD)
		return; /* netreq still in flight */

	/* TODO: Setting debug_end_time and calling 
	 * _getdns_check_dns_req_complete(netreq->owner)
	 * can be done from _getdns_netreq_change_state really.
	 * When state is changed to something finite.
	 */
	_getdns_netreq_change_state(netreq, NET_REQ_ERRORED);
	netreq->debug_end_time = _getdns_get_time_as_uintt64();
	_getdns_check_dns_req_complete(netreq->owner);
}

/* Virtual Method Tables (initialized at end of file) */

static _getdns_upstream_vmt      _base_vmt;
static _getdns_upstream_vmt   _address_vmt;
static _getdns_upstream_vmt     _named_vmt;
static _getdns_upstream_vmt   _doh_uri_vmt;
static _getdns_upstream_vmt       _udp_vmt;
static _getdns_upstream_vmt       _tcp_vmt;
static _getdns_upstream_vmt       _tls_vmt;
static _getdns_upstream_vmt       _doh_vmt;

/* Functions for _getdns_upstreams 
 *****************************************************************************/

void
_getdns_upstreams_init(_getdns_upstreams *upstreams, getdns_context *context)
{
	assert(upstreams);
	(void) memset(upstreams, 0, sizeof(_getdns_upstreams));
	upstreams->context = context;
	upstreams->super.next = &upstreams->super;
	upstreams->super.vmt  = &_base_vmt;
}

static inline _getdns_upstreams *_up_upstreams(_getdns_upstream *up)
{ if (!up) return NULL; while (up->parent) up = up->parent
; return up->vmt == &_base_vmt ? (_getdns_upstreams *)up : NULL; }

void
_getdns_context_set_upstreams(getdns_context *context, _getdns_upstreams *upstreams)
{
	_getdns_upstream *start, *current;

	assert(context);
	assert(upstreams);

	context->gups = *upstreams;
	/* Just call cleanup on one layer in the hierarchy.
	 * Individual upstreams are responsible for cleaning up their
	 * children themselfs.
	 */
	if (!(start = current = context->gups.super.children))
		; /* No children, pass */
	else do {
		current->parent = &context->gups.super;
		current = current->next;
	} while (current && current != start);
}


void
_getdns_upstreams_cleanup(_getdns_upstreams *upstreams)
{
	_getdns_upstream *start, *current;

	assert(upstreams);
	/* Just call cleanup on one layer in the hierarchy.
	 * Individual upstreams are responsible for cleaning up their
	 * children themselfs.
	 */
	if (!(start = current = upstreams->super.children))
		; /* pass */
	else do {
		UPSTREAM_CLEANUP(current);
		current = current->next;
	} while (current && current != start);

	upstreams->super.children = NULL;
}

getdns_return_t
_getdns_upstreams2list(_getdns_upstreams *upstreams, getdns_list **list_r)
{
	getdns_list *list = NULL;
	getdns_return_t r;
	getdns_dict *dict;
	_getdns_upstream *start, *current;

	assert(upstreams);

	if (!(start = current = upstreams->super.children))
		; /* pass */
	else do {
		if ((r = UPSTREAM_AS_DICT(current, &dict))) {
			if (list) getdns_list_destroy(list);
			return r;
		}
		if (!list
		&& !(list = getdns_list_create_with_context(upstreams->context)))
			return GETDNS_RETURN_MEMORY_ERROR;

		if ((r = _getdns_list_append_this_dict(list, dict))) {
			getdns_list_destroy(list);
			return r;
		}
		current = current->next;
	} while (current && current != start);

	if (!list
	&& !(list = getdns_list_create_with_context(upstreams->context)))
		return GETDNS_RETURN_MEMORY_ERROR;
	*list_r = list;
	return GETDNS_RETURN_GOOD;
}


/* Functions for _getdns_upstream data-structure traversal & maintenance 
 *****************************************************************************/

static inline getdns_context *_up_context(_getdns_upstream *upstream)
{ _getdns_upstreams *upstreams = _up_upstreams(upstream)
; return upstreams ? upstreams->context : NULL; }

static _getdns_upstream *
_simple_next_upstream(_getdns_upstream *current)
{
	if (!current || !current->next)
		return NULL;
	if (current->children)
		return current->children;
	for (;;) {
		if (!current->parent)
			return current->next;
		if (current->next != current->parent->children)
			return current->next;
		current = current->parent;
	};
}

_getdns_upstream *
_getdns_next_upstream(_getdns_upstream *current,
    upstream_caps cap, _getdns_upstream *stop_at)
{
	_getdns_upstream *start = current;

	for ( current = _simple_next_upstream(current)
	    ; current && current != start && current != stop_at
	    ; current = _simple_next_upstream(current))
		if (_upstream_cap_complies(cap, current->may))
			return current;
	return NULL;
}

static void
_upstream_append(_getdns_upstream *parent, _getdns_upstream *child)
{
	_getdns_upstream *up;

	assert(parent);
	assert(child);

	child->parent = parent;
	if (!parent->children) {
		parent->children = child;
		child->next = child;
		return;
	}
	for ( up = parent->children
	    ; up->next != parent->children
	    ; up = up->next )
		; /* pass */

	up->next = child;
	child->next = parent->children;
}

/* Functions for upstream_iter
 *****************************************************************************/

_getdns_upstream *upstream_iter_init(upstream_iter *iter,
    _getdns_upstreams *upstreams, upstream_caps cap)
{
	if (!iter) return NULL;
	iter->cap = cap;
	iter->stop_at = NULL;
	if (!(iter->current = upstreams->current[cap & CAP_TRANS])) {
		_getdns_upstream *current = upstreams->super.children;

		if (!current
		|| (!_upstream_cap_complies((cap & CAP_TRANS), current->may)
		   && !(current = _getdns_next_upstream(
				   current, (cap & CAP_TRANS), NULL))))
			return NULL;
		iter->current = upstreams->current[cap & CAP_TRANS] = current;
	}
	if (upstreams->context->round_robin_upstreams)
		upstreams->current[cap & CAP_TRANS]  =
		    _getdns_next_upstream(upstreams->current[cap & CAP_TRANS],
				    (cap & CAP_TRANS), NULL);

	if (_upstream_cap_complies(cap, iter->current->may))
		return (iter->stop_at = iter->current);

	return (iter->stop_at = iter->current =
	    _getdns_next_upstream(iter->current, cap, NULL));
}

_getdns_upstream *upstream_iter_next(upstream_iter *iter)
{
	if (!iter) return NULL;
	return (iter->current =
	    _getdns_next_upstream(iter->current, iter->cap, iter->stop_at));
}

/* netreq_next_upstream on first use returns the first upstream to use
 * on successive calls the next upstream to try is returned, untill
 * everything has been tried, then NULL is returned.
 */
static _getdns_upstream *netreq_next_upstream(getdns_network_req *netreq)
{
	_getdns_upstream *up;

	if (!netreq)
		return NULL;

	if (netreq->gup.current) {
		if ((up = upstream_iter_next(&netreq->gup)))
			return up;

		/* Try next transport */
		netreq->transport_current += 1;
	}
	while (netreq->transport_current < netreq->transport_count) {
		upstream_caps cap;

		switch (netreq->transports[netreq->transport_current]) {
		case GETDNS_TRANSPORT_UDP: cap = CAP_STATELESS | CAP_UNENCRYPTED;
		                           break;
		case GETDNS_TRANSPORT_TCP: cap = CAP_STATEFUL | CAP_UNENCRYPTED;
		                           break;
		case GETDNS_TRANSPORT_TLS: cap = CAP_STATEFUL | CAP_ENCRYPTED;
		                           if (netreq->tls_auth_min ==
		                               GETDNS_AUTHENTICATION_REQUIRED)
		                           	cap |= CAP_AUTHENTICATED;
		                           break;
		default                  : cap = 0;
		                           break;
		}
		if (netreq->owner->want_cap_resolved)
			cap |= CAP_RESOLVED;

		if ((up = upstream_iter_init(
		    &netreq->gup, &netreq->owner->context->gups, cap)))
			return up;

		/* Try next transport */
		netreq->transport_current += 1;
	}
	return NULL;
}


/* Address based upstreams
 *****************************************************************************/

typedef struct _edns_cookie_st {
	uint32_t secret;
	uint8_t  client_cookie[8];
	uint8_t  prev_client_cookie[8];
	uint8_t  server_cookie[32];

	unsigned has_client_cookie     : 1;
	unsigned has_prev_client_cookie: 1;
	unsigned has_server_cookie     : 1;
	unsigned server_cookie_len     : 5;
} _edns_cookie_st;

typedef struct _stateless_upstream {
	_getdns_upstream super;
	_edns_cookie_st  cookie;
	int              to_retry; /* (initialized to 1) */
	int              back_off; /* (initialized to 1) */
	size_t           n_responses;
	size_t           n_timeouts;
} _stateless_upstream;

static void
_stateless_upstream_init(_stateless_upstream *up)
{
	assert(up);
	up->super.vmt = &_base_vmt;
	up->super.may = CAP_MIGHT | CAP_STATELESS | CAP_UNENCRYPTED;
	up->to_retry = 1;
	up->back_off = 1;
}
static void
_udp_upstream_init(_stateless_upstream *up)
{
	assert(up);
	_stateless_upstream_init(up);
	up->super.vmt = &_udp_vmt;
}

static inline _stateless_upstream *as_udp_up(_getdns_upstream *up)
{ return up && up->vmt == &_udp_vmt ? (_stateless_upstream *)up : NULL; }

/*
 * typedef enum getdns_conn_state {
 * 	GETDNS_CONN_CLOSED,
 * 	GETDNS_CONN_SETUP,
 * 	GETDNS_CONN_OPEN,
 * 	GETDNS_CONN_TEARDOWN,
 * 	GETDNS_CONN_BACKOFF
 * } getdns_conn_state_t;
 */

typedef struct _stateful_upstream {
	_getdns_upstream        super;

	_edns_cookie_st         cookie;

	int                     fd;
	getdns_eventloop_event  event;
	getdns_eventloop       *loop;
	
	getdns_tcp_state        tcp;
	/* These are running totals or historical info */
	size_t                  conn_completed;
	size_t                  conn_shutdowns;
	size_t                  conn_setup_failed;
	time_t                  conn_retry_time;
	uint16_t                conn_backoff_interval;
	size_t                  conn_backoffs;
	size_t                  total_responses;
	size_t                  total_timeouts;
	/* These are per connection. */
	getdns_conn_state_t     conn_state;
	size_t                  queries_sent;
	size_t                  responses_received;
	size_t                  responses_timeouts;
	size_t                  keepalive_shutdown;
	uint64_t                keepalive_timeout;
	int                     server_keepalive_received;

	/* Management of outstanding requests on stateful transports */
	getdns_network_req     *write_queue;
	getdns_network_req     *write_queue_last;
	_getdns_rbtree_t        netreq_by_query_id;

	/* When requests have been scheduled asynchronously on an upstream
	 * that is kept open, and a synchronous call is then done with the
	 * upstream before all scheduled requests have been answered, answers
	 * for the asynchronous requests may be received on the open upstream.
	 * Those cannot be processed immediately, because then asynchronous
	 * callbacks will be fired as a side-effect.
	 *
	 * finished_dnsreqs is a list of dnsreqs for which answers have been
	 * received during a synchronous request.  They will be processed
	 * when the asynchronous eventloop is run.  For this the finished_event
	 * will be scheduled to the registered asynchronous event loop with a
	 * timeout of 1, so it will fire immediately (but not while scheduling)
	 * when the asynchronous eventloop is run.
	 */
	getdns_dns_req         *finished_dnsreqs;
	getdns_eventloop_event  finished_event;
	unsigned                is_sync_loop : 1;
} _stateful_upstream;

static void
_stateful_upstream_init(_stateful_upstream *up)
{
	assert(up);
	up->super.vmt = &_base_vmt;
	up->super.may = CAP_MIGHT | CAP_STATEFUL | CAP_UNENCRYPTED;
	up->fd = -1;
	up->conn_backoff_interval = 1;
	(void) getdns_eventloop_event_init(&up->event, up, NULL, NULL, NULL);
	(void) getdns_eventloop_event_init(
	    &up->finished_event, up, NULL, NULL, NULL);
}

static void
_tcp_upstream_init(_stateful_upstream *up)
{
	assert(up);
	_stateful_upstream_init(up);
	up->super.vmt = &_tcp_vmt;
}

static inline _stateful_upstream *as_tcp_up(_getdns_upstream *up)
{ return up && up->vmt == &_tcp_vmt ? (_stateful_upstream *)up : NULL; }

typedef struct _tls_upstream {
	_stateful_upstream super;
	
	/* Settings */
	uint16_t               tls_port;
        char                  *tls_cipher_list;
        char                  *tls_curves_list;
        char                   tls_auth_name[256];
        sha256_pin_t          *tls_pubkey_pinset;

	/* State */
        SSL*                   tls_obj;
        SSL_SESSION*           tls_session;
        getdns_tls_hs_state_t  tls_hs_state;
        getdns_auth_state_t    tls_auth_state;
        unsigned               tls_fallback_ok : 1;
	getdns_auth_state_t    best_tls_auth_state;
	getdns_auth_state_t    last_tls_auth_state;
} _tls_upstream;

static void
_tls_upstream_init(_tls_upstream *up)
{
	_stateful_upstream_init(&up->super);
	up->super.super.vmt = &_tls_vmt;
	up->super.super.may = CAP_MIGHT | CAP_STATEFUL | CAP_ENCRYPTED;

	/* Settings */
	up->tls_port = 853;
	up->tls_cipher_list = NULL;
	up->tls_curves_list = NULL;
	up->tls_auth_name[0] = '\0';
	up->tls_pubkey_pinset = NULL;

	/* State */
	up->tls_hs_state = GETDNS_HS_NONE;
	up->tls_auth_state = GETDNS_AUTH_NONE;
	up->last_tls_auth_state = GETDNS_AUTH_NONE;
	up->best_tls_auth_state = GETDNS_AUTH_NONE;
}

static inline _tls_upstream *as_tls_up(_getdns_upstream *up)
{ return up && up->vmt == &_tls_vmt ? (_tls_upstream *)up : NULL; }

typedef struct _doh_upstream {
	_tls_upstream super;
	
	/* settings */
	socklen_t                addr_len;
	struct sockaddr_storage  addr;
	char                     uri[4096];

	_tsig_st                 tsig;
} _doh_upstream;

static inline _doh_upstream *as_doh_up(_getdns_upstream *up)
{ return up && up->vmt == &_doh_vmt ? (_doh_upstream *)up : NULL; }

static void _doh_cleanup(_getdns_upstream *self_up)
{
	struct mem_funcs  *mfs;

	if ((mfs = priv_getdns_context_mf(_up_context(self_up)))) {
		GETDNS_FREE(*mfs, self_up);
	}
}

static const struct sockaddr *
_doh_get_addr(_getdns_upstream *self_up, socklen_t *addrlen)
{
	_doh_upstream *self = as_doh_up(self_up);

	if (self) {
		if (addrlen) *addrlen = self->addr_len;
		return (struct sockaddr *)&self->addr;
	}
	return NULL;
}

static const char *
_doh_get_name(_getdns_upstream *self_up)
{
	_doh_upstream *self = as_doh_up(self_up);
	return self ? self->uri : NULL;
}

static void _doh_set_port(_getdns_upstream *self_up, uint32_t port)
{
	_doh_upstream *self = as_doh_up(self_up);

	if (!self)
		; /* pass */

	else if (self->addr.ss_family == AF_INET)
		((struct sockaddr_in *)(&self->addr))->sin_port = htons(port);

	else if (self->addr.ss_family == AF_INET6)
		((struct sockaddr_in6 *)(&self->addr))->sin6_port = htons(port);
}

typedef struct _address_upstream {
	_getdns_upstream         super;
	
	/* settings */
	socklen_t                addr_len;
	struct sockaddr_storage  addr;
	char                     addr_str[128];

	_tsig_st                 tsig;

	/* State */
	_stateless_upstream      udp;
	_stateful_upstream       tcp;
	_tls_upstream            tls;
} _address_upstream;

static inline _address_upstream *as_address_up(_getdns_upstream *up)
{ return up && up->vmt == &_address_vmt ? (_address_upstream *)up : NULL; }

static void _address_cleanup(_getdns_upstream *self_up)
{
	struct mem_funcs  *mfs;

	if ((mfs = priv_getdns_context_mf(_up_context(self_up)))) {
		/* TODO: complete address destruction */

		GETDNS_FREE(*mfs, self_up);
	}
}

static void _address_set_port(_getdns_upstream *self_up, uint32_t port)
{
	_address_upstream *self = as_address_up(self_up);

	if (!self)
		; /* pass */

	else if (self->addr.ss_family == AF_INET)
		((struct sockaddr_in *)(&self->addr))->sin_port = htons(port);

	else if (self->addr.ss_family == AF_INET6)
		((struct sockaddr_in6 *)(&self->addr))->sin6_port = htons(port);
}

static void _address_set_tls_port(_getdns_upstream *self_up, uint32_t port)
{
	_address_upstream *self = as_address_up(self_up);

	if (self) self->tls.tls_port = port;
}

static getdns_return_t _address_as_dict(
    _getdns_upstream *self_up, getdns_dict **dict_r)
{
	_address_upstream *self = as_address_up(self_up);
	getdns_dict *dict = NULL;
	getdns_return_t r = GETDNS_RETURN_GOOD;
	getdns_bindata bindata;
	char addr_str[128], *b;
	uint16_t port;


	if (!self)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (!(dict = getdns_dict_create_with_context(_up_context(self_up))))
		return GETDNS_RETURN_MEMORY_ERROR;

	switch (self->addr.ss_family) {
	case AF_INET:
		if ((r = getdns_dict_util_set_string(dict, "address_type", "IPv4")))
			break;

		bindata.size = 4;
		bindata.data = (void *)&((struct sockaddr_in *)(&self->addr))->sin_addr;
		if ((r = getdns_dict_set_bindata(dict, "address_data", &bindata)))
			break;

		port = ntohs(((struct sockaddr_in *)(&self->addr))->sin_port);
		if (port != 0 && port != 53)
		    r = getdns_dict_set_int(dict, "port", (uint32_t)port);

		break;

	case AF_INET6:
		if ((r = getdns_dict_util_set_string(dict, "address_type", "IPv6")))
			break;

		bindata.size = 16;
		bindata.data = (void *)&((struct sockaddr_in6 *)(&self->addr))->sin6_addr;
		if ((r = getdns_dict_set_bindata(dict, "address_data", &bindata)))
			break;

		port = ntohs(((struct sockaddr_in6 *)(&self->addr))->sin6_port);
		if (port != 0 && port != 53 &&
		    (r = getdns_dict_set_int(dict, "port", (uint32_t)port)))
			break;

		/* Try to get scope_id too */
		if (getnameinfo((struct sockaddr *)(&self->addr), self->addr_len,
		    addr_str, sizeof(addr_str), NULL, 0, NI_NUMERICHOST))
			break;

		if ((b = strchr(addr_str, '%')))
		    r = getdns_dict_util_set_string(dict, "scope_id", b + 1);

		break;
	default:
		r = GETDNS_RETURN_NOT_IMPLEMENTED;
		break;
	}
	if (!r) do {
		if (self->tls.tls_port != 853 &&
		    (r = getdns_dict_set_int(dict, "tls_port", (uint32_t)self->tls.tls_port)))
			break;
	} while(0);
	if (r) {
		getdns_dict_destroy(dict);
		return r;
	}
	*dict_r = dict;
	return GETDNS_RETURN_GOOD;
}

static const char *
_address_get_name(_getdns_upstream *self_up)
{
	_address_upstream *self = as_address_up(self_up);
	return self ? self->addr_str : NULL;
}

static const struct sockaddr *
_address_get_addr(_getdns_upstream *self_up, socklen_t *addrlen)
{
	_address_upstream *self = as_address_up(self_up);

	if (self) {
		if (addrlen)
			*addrlen = self->addr_len;
		return (struct sockaddr *)&self->addr;
	}
	return NULL;
}

static getdns_return_t
_getdns_create_address_upstream(struct mem_funcs *mfs,
    struct addrinfo *ai, const char *addr_str, _getdns_upstream **new_upstream)
{
	_address_upstream *up;

	assert(ai);
	assert(addr_str);

	if (!(up = GETDNS_MALLOC(*mfs, _address_upstream)))
		return GETDNS_RETURN_MEMORY_ERROR;

	(void) memset(up, 0, sizeof(*up));
	up->super.children           = &up->udp.super;
	up->super.vmt                = &_address_vmt;

	up->udp.super.parent         = &up->super;
	up->udp.super.children       = NULL;
	up->udp.super.next           = &up->tcp.super;

	up->tcp.super.parent         = &up->super;
	up->tcp.super.children       = NULL;
	up->tcp.super.next           = &up->tls.super.super;

	up->tls.super.super.parent   = &up->super;
	up->tls.super.super.children = NULL;
	up->tls.super.super.next     = &up->udp.super;

	_udp_upstream_init(&up->udp);
	_tcp_upstream_init(&up->tcp);
	_tls_upstream_init(&up->tls);

	(void) strlcpy(up->addr_str, addr_str, sizeof(up->addr_str));

	up->addr_len = ai->ai_addrlen;
	(void) memcpy(&up->addr, ai->ai_addr, ai->ai_addrlen);
	up->addr.ss_family = ai->ai_family;
	up->tsig.tsig_alg = GETDNS_NO_TSIG;

	if (new_upstream)
		*new_upstream = &up->super;

	return GETDNS_RETURN_GOOD;
}

typedef struct _named_upstream {
	_getdns_upstream         super;
	
	/* Settings */
	char                     name[1024];
	uint16_t                 port;
	uint16_t                 tls_port;
	_tsig_st                 tsig;

	/* State */
	getdns_eventloop        *loop;
	getdns_network_req      *req_a;
	getdns_network_req      *req_aaaa;
	getdns_network_req      *fifo;
	getdns_network_req      *fifo_last;
	unsigned int             done_a   : 1;
	unsigned int             done_aaaa: 1;
} _named_upstream;

static inline _named_upstream *as_named_up(_getdns_upstream *up)
{ return up && (  up->vmt == &_named_vmt
               || up->vmt == &_doh_uri_vmt) ? (_named_upstream *)up : NULL; }

static void netreq_fifo_add(
    getdns_network_req **fifo, getdns_network_req **fifo_last,
    getdns_network_req *netreq)
{
	assert(fifo && fifo_last && netreq);

	assert(netreq->write_queue_tail == NULL);
	if (!*fifo) {
		assert(!*fifo_last);
		*fifo = *fifo_last = netreq;
	} else {
		(*fifo_last)->write_queue_tail = netreq;
		 *fifo_last = netreq;
	}
}

static void netreq_fifo_remove(
    getdns_network_req **fifo, getdns_network_req **fifo_last,
    getdns_network_req *netreq)
{
	getdns_network_req *r, *prev_r;

	assert(fifo && fifo_last && netreq);

	for ( r = *fifo, prev_r = NULL
	    ; r ; prev_r = r, r = r->write_queue_tail) {
		if (r != netreq)
			continue;

		/* netreq found */
		if (prev_r)
			prev_r->write_queue_tail = r->write_queue_tail;
		else
			*fifo = r->write_queue_tail;
		
		if (r == *fifo_last) {
			/* If r was the last netreq,
			 * its write_queue_tail MUST be NULL
			 */
			assert(r->write_queue_tail == NULL);
			*fifo_last = prev_r;
		}
		netreq->write_queue_tail = NULL;
		return;
	}
}

typedef struct _doh_uri_upstream {
	_named_upstream super;
	
	/* Settings */
	char            uri[4096];
	char           *path;
} _doh_uri_upstream;

static inline _doh_uri_upstream *as_doh_uri_up(_getdns_upstream *up)
{ return up && up->vmt == &_doh_uri_vmt ? (_doh_uri_upstream *)up : NULL; }

static getdns_return_t
_getdns_append_doh_upstream(_getdns_upstream *parent_up,
    struct addrinfo *ai, const char *addr_str, _getdns_upstream **new_upstream)
{
	_doh_uri_upstream *parent = as_doh_uri_up(parent_up);
	struct mem_funcs *mfs = priv_getdns_context_mf(_up_context(parent_up));
	_doh_upstream *up;

	assert(ai);
	assert(addr_str);

	if (!parent || !mfs)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (!(up = GETDNS_MALLOC(*mfs, _doh_upstream)))
		return GETDNS_RETURN_MEMORY_ERROR;

	(void) memset(up, 0, sizeof(*up));
	_tls_upstream_init(&up->super);
	up->super.tls_port = 443;
	up->super.super.super.vmt = &_doh_vmt;
	(void)snprintf(up->uri, sizeof(up->uri),
	    "https://%s/%s", addr_str, parent->path);

	up->addr_len = ai->ai_addrlen;
	(void) memcpy(&up->addr, ai->ai_addr, ai->ai_addrlen);
	up->addr.ss_family = ai->ai_family;
	up->tsig.tsig_alg = GETDNS_NO_TSIG;

	_upstream_append(parent_up, &up->super.super.super);
	if (new_upstream)
		*new_upstream = &up->super.super.super;
	return GETDNS_RETURN_GOOD;
}

static void _named_address_answer_cb(
    _named_upstream *self, getdns_network_req **netreq,
    size_t addrlen, int af)
{
	_getdns_rrset_spc    rrset_spc;
	_getdns_rrset       *rrset;
	_getdns_rrtype_iter  rr_spc;
	_getdns_rrtype_iter *rr;
	char                 a_buf[40];

	DEBUG_STUB("%s %-35s: MSG: %p TYPE: %d\n", STUB_DEBUG_ENTRY, __FUNC__,
	           (void*)*netreq, (*netreq)->request_type);

	if (!(rrset = _getdns_rrset_answer(&rrset_spc,
	    (*netreq)->response, (*netreq)->response_len)))
		; /* pass; maybe NXDOMAIN */

	else for ( rr = _getdns_rrtype_iter_init(&rr_spc, rrset)
	         ; rr ; rr = _getdns_rrtype_iter_next(rr)) {
		_getdns_upstream *new_upstream;

		 if (rr->rr_i.nxt - rr->rr_i.rr_type != (int)(10 + addrlen))
			 continue;
		(void) inet_ntop(af, rr->rr_i.rr_type + 10, a_buf, sizeof(a_buf));
		fprintf(stderr, "Address lookup (for DoH): %s\n", a_buf);

		/* TODO: Replace this with pass in native address data */
		if (self->super.vmt == &_doh_uri_vmt) {
			struct addrinfo   hints;
			struct addrinfo  *ai = NULL;

			(void) memset(&hints, 0, sizeof(struct addrinfo));
			hints.ai_family    = AF_UNSPEC;      /* IPv4 or IPv6 */
			hints.ai_flags     = AI_NUMERICHOST; /* No reverse lookups */

			if (!getaddrinfo(a_buf, "443", &hints, &ai) &&
			    !_getdns_append_doh_upstream(
					&self->super, ai, a_buf, &new_upstream) &&
			    self->port != 443)
				new_upstream->vmt->set_port(new_upstream, self->port);

		} else if (!_getdns_append_upstream(
		    &self->super, a_buf, &new_upstream)) {
			if (self->port != 53)
				new_upstream->vmt->set_port(new_upstream, self->port);
			if (self->tls_port != 853)
				new_upstream->vmt->set_tls_port(
				    new_upstream, self->tls_port);
		}
	}
	*netreq = NULL;

	/* If all lookups are done, remove capabilities,
	 * so no new queries will be queued.
	 */
	if (self->done_a && !self->req_a && self->done_aaaa && !self->req_aaaa)
		self->super.may  = 0;

	/* Resubmit queued children */
	if (self->super.children) {
		getdns_network_req *req = self->fifo;
		uint64_t now_ms = 0;

		self->fifo = self->fifo_last = NULL;
		while (req) {
			getdns_network_req *next = req->write_queue_tail;
			req->write_queue_tail = NULL;

			_fallback_resubmit_netreq(req, &now_ms);

			req = next;
		}
	}
}

static void _named_a_answer_cb(getdns_dns_req *dnsreq)
{
	_named_upstream     *self = (_named_upstream *)dnsreq->user_pointer;
	_named_address_answer_cb(self, &self->req_a, 4, AF_INET);
}

static void _named_aaaa_answer_cb(getdns_dns_req *dnsreq)
{
	_named_upstream     *self = (_named_upstream *)dnsreq->user_pointer;
	_named_address_answer_cb(self, &self->req_aaaa, 16, AF_INET6);
}

static int _named_submit(
    _getdns_upstream *self_up, getdns_network_req *netreq, uint64_t *now_ms)
{
	getdns_return_t r;
	getdns_context *context = NULL;
	_named_upstream *self = as_named_up(self_up);

	(void)now_ms;

	DEBUG_STUB("%s %-35s: MSG: %p TYPE: %d\n", STUB_DEBUG_ENTRY, __FUNC__,
	           (void*)netreq, netreq->request_type);

	if (!self)
		return STUB_TRY_NEXT_UPSTREAM;

	if (!self->done_aaaa && !self->req_aaaa) {
		/* Schedule AAAA request */
		self->done_aaaa = 1;
		if (!context)
			context = _getdns_context_get_sys_ctxt(
			    _up_context(self_up), netreq->owner->loop);

		/* TODO: Allow query with alternative transport list
		 * intead of using sys_ctxt
		 */
		if (context && (r = _getdns_general_loop(context,
		    netreq->owner->loop, self->name, GETDNS_RRTYPE_AAAA,
		    want_cap_resolved, self, &self->req_aaaa, NULL,
		    _named_aaaa_answer_cb)))
			(void)r; /* TODO: Log error */
	}
	if (!self->done_a && !self->req_a) {
		/* Schedule A request */
		self->done_a = 1;
		if (!context)
			context = _getdns_context_get_sys_ctxt(
			    _up_context(self_up), netreq->owner->loop);

		/* TODO: Allow query with alternative transport list
		 * intead of using sys_ctxt
		 */
		if (context && (r = _getdns_general_loop(context,
		    netreq->owner->loop, self->name, GETDNS_RRTYPE_A,
		    want_cap_resolved, self, &self->req_a, NULL,
		    _named_a_answer_cb)))
			(void)r; /* TODO: Log error */
	}
	if (self->req_a || self->req_aaaa) {
		/* Append to fifo */
		netreq_fifo_add(&self->fifo, &self->fifo_last, netreq);
		/* TODO: Schedule timeout */
		return GETDNS_RETURN_GOOD;
	}
	return STUB_TRY_NEXT_UPSTREAM;
}

static void _named_revoke(
    _getdns_upstream *self_up, getdns_network_req *netreq)
{
	_named_upstream *self = as_named_up(self_up);
	DEBUG_STUB("%s %-35s: MSG: %p\n", STUB_DEBUG_CLEANUP, __FUNC__, (void*)netreq);

	if (netreq && netreq->event.ev)
		GETDNS_CLEAR_EVENT(netreq->owner->loop, &netreq->event);

	if (self)
		netreq_fifo_remove(&self->fifo, &self->fifo_last, netreq);
}

static void _named_erred(_getdns_upstream *self_up)
{
	/* _named_upstream *self = as_named_up(self_up); */
	(void)(self_up);
}

static void _named_cleanup(_getdns_upstream *self_up)
{
	_getdns_upstream *up;
	struct mem_funcs *mfs;

	if (!self_up)
		return;

	for (up = self_up->children; up; up = up->next) {
		UPSTREAM_CLEANUP(up);
	}
	self_up->children = NULL;
	if ((mfs = priv_getdns_context_mf(_up_context(self_up)))) {
		/* TODO: complete destruction */

		GETDNS_FREE(*mfs, self_up);
	}
}

static void _named_set_port(_getdns_upstream *self_up, uint32_t port)
{
	_named_upstream *self = as_named_up(self_up);
	self->port = port;
}

static void _named_set_tls_port(_getdns_upstream *self_up, uint32_t tls_port)
{
	_named_upstream *self = as_named_up(self_up);
	self->tls_port = tls_port;
}

static getdns_return_t _named_as_dict(
    _getdns_upstream *self_up, getdns_dict **dict_r)
{
	_named_upstream *self = as_named_up(self_up);
	getdns_dict *dict = NULL;
	getdns_return_t r = GETDNS_RETURN_GOOD;

	if (!self)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (!(dict = getdns_dict_create_with_context(_up_context(self_up))))
		return GETDNS_RETURN_MEMORY_ERROR;

	if ((r = getdns_dict_util_set_string(dict, "name", self->name)))
		; /* error */

	else if (self->port != 53 &&
	    (r = getdns_dict_set_int(dict, "port", (uint32_t)self->port)))
		; /* error */

	else if (self->tls_port != 853 &&
	    (r = getdns_dict_set_int(dict, "tls_port", (uint32_t)self->tls_port)))
		; /* error */

	else {
		*dict_r = dict;
		return GETDNS_RETURN_GOOD;
	}
	getdns_dict_destroy(dict);
	return r;
}

static const char *_named_get_name(_getdns_upstream *self_up)
{
	_named_upstream *self = as_named_up(self_up);
	return self ? self->name : "<NO NAME>";
}


static void
_named_upstream_init(_named_upstream *up, const char *name)
{
	(void) memset(up, 0, sizeof(*up));
	up->super.vmt = &_named_vmt;
	up->super.may = (CAP_MIGHT     & (CAP_RESOLVED ^ 0xFFFF))
	              |  CAP_STATELESS |  CAP_UNENCRYPTED
		      |  CAP_STATEFUL  |  CAP_ENCRYPTED;

	(void) strlcpy(up->name, name, sizeof(up->name));
	up->port = 53;
	up->tls_port = 853;
}

static getdns_return_t
_getdns_create_named_upstream(struct mem_funcs *mfs,
    const char *name, _getdns_upstream **new_upstream)
{
	_named_upstream *up;

	if (!(up = GETDNS_MALLOC(*mfs, _named_upstream)))
		return GETDNS_RETURN_MEMORY_ERROR;

	_named_upstream_init(up, name);

	if (new_upstream)
		*new_upstream = &up->super;

	return GETDNS_RETURN_GOOD;
}

static getdns_return_t
_getdns_create_doh_uri_upstream(struct mem_funcs *mfs,
    const char *uri, _getdns_upstream **new_upstream)
{
	_doh_uri_upstream *up;

	if (!(up = GETDNS_MALLOC(*mfs, _doh_uri_upstream)))
		return GETDNS_RETURN_MEMORY_ERROR;

	(void) strlcpy(up->uri, uri, sizeof(up->uri));
	if (strlen(up->uri) > 8) {
		/* TODO: https on different port */
		char *slash = strchr(up->uri + 8, '/');

		if (slash) {
			*slash = '\0';
			up->path = slash + 1;
		} else {
			up->path = up->uri + strlen(up->uri);
		}
		_named_upstream_init(&up->super, up->uri + 8);
		if (slash) *slash = '/';
	} else {
		GETDNS_FREE(*mfs, up);
		return GETDNS_RETURN_INVALID_PARAMETER;
	}
	up->super.super.vmt = &_doh_uri_vmt;
	up->super.tls_port = 443;
	if (new_upstream)
		*new_upstream = &up->super.super;

	return GETDNS_RETURN_GOOD;
}

static getdns_return_t _doh_uri_as_dict(
    _getdns_upstream *self_up, getdns_dict **dict_r)
{
	_doh_uri_upstream *self = as_doh_uri_up(self_up);
	getdns_dict *dict = NULL;
	getdns_return_t r = GETDNS_RETURN_GOOD;

	if (!self)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (!(dict = getdns_dict_create_with_context(_up_context(self_up))))
		return GETDNS_RETURN_MEMORY_ERROR;

	if ((r = getdns_dict_util_set_string(dict, "uri", self->uri)))
		; /* error */
	else {
		*dict_r = dict;
		return GETDNS_RETURN_GOOD;
	}
	getdns_dict_destroy(dict);
	return r;
}

static const char *_doh_uri_get_name(_getdns_upstream *self_up)
{ _doh_uri_upstream *self = as_doh_uri_up(self_up); return self->uri; }

static const char *_doh_get_transport_name(_getdns_upstream *self_up)
{ (void)self_up; return "HTTPS"; }

getdns_return_t
_getdns_append_upstream(_getdns_upstream *parent,
    const char *addr_str, _getdns_upstream **new_upstream)
{
	struct addrinfo   hints;
	struct addrinfo  *ai = NULL;
	getdns_return_t   r;
	_getdns_upstream *up = NULL;
	struct mem_funcs *mfs;


	assert(parent);
	assert(addr_str); /* contract for usage within library*/

	if (!(mfs = priv_getdns_context_mf(_up_context(parent))))
		return GETDNS_RETURN_GENERIC_ERROR;

	(void) memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family    = AF_UNSPEC;      /* Allow IPv4 or IPv6 */
	hints.ai_flags     = AI_NUMERICHOST; /* No reverse name lookups */

	if (getaddrinfo(addr_str, "53", &hints, &ai) || !ai) {
		if ((addr_str[0] == 'h' || addr_str[0] == 'H') &&
		    (addr_str[1] == 't' || addr_str[1] == 'T') &&
		    (addr_str[2] == 't' || addr_str[2] == 'T') &&
		    (addr_str[3] == 'p' || addr_str[3] == 'P') &&
		    (addr_str[4] == 's' || addr_str[4] == 'S') &&
		     addr_str[5] == ':' &&
		     addr_str[6] == '/' && addr_str[7] == '/')
			r = _getdns_create_doh_uri_upstream(mfs, addr_str, &up);
		else
			r = _getdns_create_named_upstream(mfs, addr_str, &up);
	} else
		r = _getdns_create_address_upstream(mfs, ai, addr_str, &up);
	freeaddrinfo(ai);
	if (r)
		return r;
	_upstream_append(parent, up);
	if (new_upstream)
		*new_upstream = up;
	return GETDNS_RETURN_GOOD;
}

ssize_t _prepare_netreq_packet_for_send(_getdns_upstream *up,
    getdns_network_req *netreq, _edns_cookie_st *cookie, _tsig_st *tsig)
{
	GLDNS_ID_SET(netreq->query, (uint16_t)arc4random());
	if (netreq->opt) {
		_getdns_network_req_clear_upstream_options(netreq);

		if (netreq->owner->edns_cookies) {
			/* TODO: Handle cookies */
			(void)cookie;
		}

		if (netreq->owner->edns_client_subnet_private) {
			const struct sockaddr *addr = UPSTREAM_GET_ADDR(up, NULL);

			/* see https://tools.ietf.org/html/rfc7871#section-7.1.2
			 * all-zeros is a request to not leak the data further:
			 * A two byte FAMILY field is a SHOULD even when SOURCE
			 * and SCOPE are 0.
			 * "\x00\x02"  FAMILY: 2 for IPv6 upstreams in network byte order, or
			 * "\x00\x01"  FAMILY: 1 for IPv4 upstreams in network byte order, then:
			 * "\x00"  SOURCE PREFIX-LENGTH: 0
			 * "\x00";  SCOPE PREFIX-LENGTH: 0
			 */
			if (_getdns_network_req_add_upstream_option(
			    netreq, GLDNS_EDNS_CLIENT_SUBNET, 4,
			    ( !addr || addr->sa_family != AF_INET6
			    ? "\x00\x01\x00\x00" : "\x00\x02\x00\x00" )))
				return -1;
		}
	}
	if (!tsig || tsig->tsig_alg == GETDNS_NO_TSIG_)
		return netreq->response - netreq->query;

	return -1; /* TODO: Add tsig option */
}

static void
_udp_revoke(_getdns_upstream *self_up, getdns_network_req *netreq)
{
	DEBUG_STUB("%s %-35s: MSG: %p\n", STUB_DEBUG_CLEANUP, __FUNC__, (void*)netreq);
	(void)self_up;

	if (netreq->event.ev)
		GETDNS_CLEAR_EVENT(netreq->owner->loop, &netreq->event);
	if (netreq->fd >= 0) {
		_getdns_closesocket(netreq->fd);
		netreq->fd = -1;
	}
}

static void
_udp_erred(_getdns_upstream *self_up)
{
	_stateless_upstream *self = as_udp_up(self_up);

	if (self && --self->to_retry == 0) {
		if (self->back_off * 2 >   _up_context(self_up)->max_backoff_value)
			self->to_retry = -(_up_context(self_up)->max_backoff_value);
		else	self->to_retry = -(self->back_off * 2);
	}
}

static void
_udp_timeout_cb(void *userarg)
{
	getdns_network_req *netreq = (getdns_network_req *)userarg;

	assert(netreq);
	if (!netreq->gup.current)
		_udp_revoke(NULL, netreq);
	else {
		UPSTREAM_REVOKE(netreq->gup.current, netreq);
		UPSTREAM_ERRED(netreq->gup.current);
	}
	_getdns_netreq_change_state(netreq, NET_REQ_TIMED_OUT);
	netreq->debug_end_time = _getdns_get_time_as_uintt64();
	_getdns_check_dns_req_complete(netreq->owner);
}

static void
_udp_read_cb(void *userarg)
{
	getdns_network_req *netreq = (getdns_network_req *)userarg;
	uint64_t now_ms = 0;
	getdns_dns_req *dnsreq = netreq->owner;
	_stateless_upstream *up = as_udp_up(netreq->gup.current);
	ssize_t       read;
	DEBUG_STUB("%s %-35s: MSG: %p \n", STUB_DEBUG_READ, __FUNC__, (void*)netreq);

	read = recvfrom(netreq->fd, (void *)netreq->response,
	    netreq->max_udp_payload_size + 1, /* If read == max_udp_payload_size
	                                       * then all is good.  If read ==
	                                       * max_udp_payload_size + 1, then
	                                       * we receive more then requested!
	                                       * i.e. overflow
	                                       */
	    0, NULL, NULL);
	if (read == -1 && (_getdns_socketerror_wants_retry() ||
		           _getdns_socketerror() == _getdns_ECONNRESET))
		return; /* Try again later */

	if (read == -1) {
		DEBUG_STUB("%s %-35s: MSG: %p error while reading from socket:"
		           " %s\n", STUB_DEBUG_READ, __FUNC__, (void*)netreq
			   , _getdns_errnostr());

		if (!up)
			_udp_revoke(NULL, netreq);
		else {
			UPSTREAM_REVOKE(&up->super, netreq);
			UPSTREAM_ERRED(&up->super);
		}
		_fallback_resubmit_netreq(netreq, &now_ms);
		return;
	}
	if (read < GLDNS_HEADER_SIZE)
		return; /* Not DNS, wait for proper packet */
	
	if (GLDNS_ID_WIRE(netreq->response) != GLDNS_ID_WIRE(netreq->query))
		return; /* Cache poisoning attempt ;), wait for proper packet */

	/* TODO: Cookie validation
	if (netreq->owner->edns_cookies && match_and_process_server_cookie(
	    upstream, netreq->response, read))
		return;
	*/
	if (up)
		UPSTREAM_REVOKE(&up->super, netreq);
	else	_udp_revoke(NULL, netreq);
	if (GLDNS_TC_WIRE(netreq->response)) {
		DEBUG_STUB("%s %-35s: MSG: %p TC bit set in response \n", STUB_DEBUG_READ, 
		             __FUNC__, (void*)netreq);
		/* TODO: tc bit handling */
	}
	netreq->response_len = read;
	netreq->debug_end_time = _getdns_get_time_as_uintt64();
	if (up) {
		up->n_responses++;
		up->back_off = 1;
		if (up->n_responses % 100 == 1)
			_getdns_context_log(_up_context(&up->super),
			    GETDNS_LOG_UPSTREAM_STATS, GETDNS_LOG_INFO,
			    "%-40s : Upstream   : %s - Resps=%6d, Timeouts"
			    "  =%6d (logged every 100 responses)\n",
			    UPSTREAM_GET_NAME(&up->super),
			    UPSTREAM_GET_TRANSPORT_NAME(&up->super),
			    (int)up->n_responses, (int)up->n_timeouts);
	}
	_getdns_netreq_change_state(netreq, NET_REQ_FINISHED);
	_getdns_check_dns_req_complete(dnsreq);
}


int
_udp_write(_stateless_upstream *self, getdns_network_req *netreq, uint64_t *now_ms)
{
	getdns_dns_req        *dnsreq = netreq->owner;
	ssize_t                pkt_len;
	ssize_t                written;
	socklen_t              addrlen;
	const struct sockaddr *addr = UPSTREAM_GET_ADDR(&self->super, &addrlen);

	DEBUG_STUB("%s %-35s: MSG: %p \n", STUB_DEBUG_WRITE, 
	             __FUNC__, (void *)netreq);

	if (netreq->event.ev)
		GETDNS_CLEAR_EVENT(dnsreq->loop, &netreq->event);

	if (!addr || (pkt_len = _prepare_netreq_packet_for_send(
	    &self->super, netreq, &self->cookie, NULL)) < 0) /* TODO: pass TSIG */
		return GETDNS_RETURN_GENERIC_ERROR;

	if (netreq->opt) {
		/* Relevant for UDP only */
		if (netreq->edns_maximum_udp_payload_size == -1)
			gldns_write_uint16(netreq->opt + 3,
			    ( netreq->max_udp_payload_size =
			      addr->sa_family == AF_INET6 ? 1232 : 1432));
	}
	if (pkt_len != (written = sendto(netreq->fd,
	    (const void *)netreq->query, (size_t)pkt_len, 0, addr, addrlen))) {

#if defined(STUB_DEBUG) && STUB_DEBUG
		if (written == -1)
			DEBUG_STUB( "%s %-35s: MSG: %p error: %s\n"
				  , STUB_DEBUG_WRITE, __FUNC__, (void *)netreq
				  , _getdns_errnostr());
		else
			DEBUG_STUB( "%s %-35s: MSG: %p returned: %d, expected: %d\n"
				  , STUB_DEBUG_WRITE, __FUNC__, (void *)netreq
				  , (int)written, (int)pkt_len);
#else
		(void)written;
#endif
		return GETDNS_RETURN_IO_ERROR;
	}
	netreq->debug_start_time = _getdns_get_time_as_uintt64();
	netreq->debug_udp = 1;

	GETDNS_SCHEDULE_EVENT(dnsreq->loop, netreq->fd,
	    _getdns_ms_until_expiry2(dnsreq->expires, now_ms),
	    getdns_eventloop_event_init(&netreq->event, netreq,
	    _udp_read_cb, NULL, _udp_timeout_cb));

	return GETDNS_RETURN_GOOD;
}

static void
_udp_write_cb(void *userarg)
{
	getdns_network_req *netreq = (getdns_network_req *)userarg;
	uint64_t now_ms = 0;
	DEBUG_STUB("%s %-35s: MSG: %p \n", STUB_DEBUG_WRITE, 
	             __FUNC__, (void *)netreq);

	if (_udp_write(as_udp_up(netreq->gup.current), netreq, &now_ms)) {
		_udp_revoke(netreq->gup.current, netreq);
		_udp_erred(netreq->gup.current);
		_fallback_resubmit_netreq(netreq, &now_ms);
	}
}

int
_udp_submit(_getdns_upstream *self_up,
    getdns_network_req *netreq, uint64_t *now_ms)
{
	_stateless_upstream   *self = as_udp_up(self_up);
	socklen_t              addrlen;
	const struct sockaddr *addr = UPSTREAM_GET_ADDR(self_up, &addrlen);

	DEBUG_STUB("%s %-35s: MSG: %p TYPE: %d\n", STUB_DEBUG_ENTRY, __FUNC__,
	           (void*)netreq, netreq->request_type);

	if (!self)
		return STUB_TRY_NEXT_UPSTREAM;

	if (  self->to_retry <= 0 &&
	    ++self->to_retry <= 0)
		return STUB_TRY_NEXT_UPSTREAM;

	if (!addr)
		return GETDNS_RETURN_GENERIC_ERROR;

	netreq->fd = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (netreq->fd < 0)
		return _getdns_resource_depletion()
		     ? STUB_TRY_AGAIN_LATER
		     : (int)GETDNS_RETURN_IO_ERROR;

	_getdns_sock_nonblock(netreq->fd);
	if (netreq->owner->write_udp_immediately)
		return _udp_write(self, netreq, now_ms);

	return GETDNS_SCHEDULE_EVENT(netreq->owner->loop, netreq->fd,
	    _getdns_ms_until_expiry2(netreq->owner->expires, now_ms),
	     getdns_eventloop_event_init(&netreq->event, netreq,
		     NULL, _udp_write_cb, _udp_timeout_cb));
}

getdns_return_t
_getdns_submit_stub_request(getdns_network_req *netreq, uint64_t *now_ms)
{
	_getdns_upstream *up;
	DEBUG_STUB("%s %-35s: MSG: %p TYPE: %d\n", STUB_DEBUG_ENTRY, __FUNC__,
	           (void*)netreq, netreq->request_type);

	assert(netreq);

	/* Find upstream for current transport */
	while ((up = netreq_next_upstream(netreq))) {
		switch (UPSTREAM_SUBMIT(up, netreq, now_ms)) {
		case GETDNS_RETURN_GOOD:
			return GETDNS_RETURN_GOOD;

		case STUB_TRY_AGAIN_LATER:
			_getdns_netreq_change_state(netreq, NET_REQ_NOT_SENT);
			netreq->node.key = netreq;
			if (_getdns_rbtree_insert(
			    &netreq->owner->context->pending_netreqs, &netreq->node))
				return GETDNS_RETURN_GOOD;
			return GETDNS_RETURN_NO_UPSTREAM_AVAILABLE;

		case STUB_TRY_NEXT_UPSTREAM:
			break;

		default:
			/* Not submitted, so no revoke needed */
			UPSTREAM_ERRED(up);
			break;
		}
	}
	return GETDNS_RETURN_NO_UPSTREAM_AVAILABLE;
}

void
_getdns_cancel_stub_request(getdns_network_req *netreq)
{
	DEBUG_STUB("%s %-35s: MSG: %p\n",
	           STUB_DEBUG_CLEANUP, __FUNC__, (void*)netreq);
	if (netreq->gup.current)
		UPSTREAM_REVOKE(netreq->gup.current, netreq);
	else	_udp_revoke(NULL, netreq);
	_getdns_netreq_change_state(netreq, NET_REQ_CANCELED);
	netreq->debug_end_time = _getdns_get_time_as_uintt64();
	/* Do not call _getdns_check_dns_req_complete(netreq->owner);
	 * since that will trigger callbacks, which we do not want
	 * with explicit canceling.
	 */
}

/* Virtual Method Tables */

static void _nop_cleanup(_getdns_upstream *self)
{ (void)self; }
static void _nop_uint32_t(_getdns_upstream *self, uint32_t n)
{ (void)self; (void)n; }
static const struct sockaddr *
_nop_get_addr(_getdns_upstream *self, socklen_t *addrlen)
{ (void)self; (void)addrlen; return NULL; }
static getdns_return_t _nop_as_dict(
    _getdns_upstream *self, getdns_dict **dict_r)
{ (void)self; (void)dict_r; return GETDNS_RETURN_NOT_IMPLEMENTED; }
static const char *_nop_get_transport_name(_getdns_upstream *self)
{ (void)self; return "<NO TRANSPORT>"; }
static const char *_nop_get_name(_getdns_upstream *self)
{ (void)self; return "<NO NAME>"; }


static int _nop_submit(
    _getdns_upstream *self, getdns_network_req *netreq, uint64_t *now_ms)
{ (void)self; (void)netreq; (void)now_ms
; fprintf(stderr, "Submit netreq %p with transport %s on upstream %p for %s\n", (void *)netreq, UPSTREAM_GET_TRANSPORT_NAME(self), (void *)self, UPSTREAM_GET_NAME(self))
; return GETDNS_RETURN_NOT_IMPLEMENTED; }
static void _nop_revoke(_getdns_upstream *self, getdns_network_req *netreq)
{ (void)self; (void)netreq; ; fprintf(stderr, "Revoke netreq %p with transport %s on upstream %p for %s\n", (void *)netreq, UPSTREAM_GET_TRANSPORT_NAME(self), (void *)self, UPSTREAM_GET_NAME(self)); }
static void _nop_erred(_getdns_upstream *self)
{ (void)self; fprintf(stderr, "Upstream %p for %s with transport %s erred\n", (void *)self, UPSTREAM_GET_NAME(self), UPSTREAM_GET_TRANSPORT_NAME(self)); }

static void _set_parent_port(_getdns_upstream *self, uint32_t port)
{
	assert(self);
	if (self->parent)
		self->parent->vmt->set_port(self->parent, port);
}

static void _set_parent_tls_port(_getdns_upstream *self, uint32_t port)
{
	assert(self);
	if (self->parent)
		self->parent->vmt->set_tls_port(self->parent, port);
}

static const struct sockaddr *
_get_parent_addr(_getdns_upstream *self, socklen_t *len)
{ return self && self->parent ? UPSTREAM_GET_ADDR(self->parent, len) : NULL; }

static const char *_get_parent_name(_getdns_upstream *self)
{ return self && self->parent
       ? UPSTREAM_GET_NAME(self->parent) : "<NO PARENT NAME>"; }

static const char *_udp_get_transport_name(_getdns_upstream *self)
{ (void)self; return "UDP"; }

static const char *_tcp_get_transport_name(_getdns_upstream *self)
{ (void)self; return "TCP"; }

static const char *_tls_get_transport_name(_getdns_upstream *self)
{ (void)self; return "TLS"; }

static _getdns_upstream_vmt _base_vmt = {
	_nop_cleanup,
	_nop_uint32_t,
	_nop_uint32_t,
	_nop_as_dict,
	_nop_get_name,
	_nop_get_addr,
	_nop_get_transport_name,

	_nop_submit,
	_nop_revoke,
	_nop_erred,
};
static _getdns_upstream_vmt   _address_vmt = {
	_address_cleanup,
	_address_set_port,
	_address_set_tls_port,
	_address_as_dict,
	_address_get_name,
	_address_get_addr,
	_nop_get_transport_name,

	_nop_submit,
	_nop_revoke,
	_nop_erred,
};
static _getdns_upstream_vmt   _named_vmt = {
	_named_cleanup,
	_named_set_port,
	_named_set_tls_port,
	_named_as_dict,
	_named_get_name,
	_nop_get_addr,
	_nop_get_transport_name,

	_named_submit,
	_named_revoke,
	_named_erred,
};
static _getdns_upstream_vmt   _doh_uri_vmt = {
	_named_cleanup,
	_named_set_port,
	_named_set_port,
	_doh_uri_as_dict,
	_doh_uri_get_name,
	_nop_get_addr,
	_doh_get_transport_name,

	_named_submit,
	_named_revoke,
	_named_erred,
};
static _getdns_upstream_vmt       _udp_vmt = {
	_nop_cleanup,		/* Handled by _address parent */
	_set_parent_port,
	_set_parent_tls_port,
	_nop_as_dict,		/* Handled by _address parent */
	_get_parent_name,
	_get_parent_addr,
	_udp_get_transport_name,

	_udp_submit,
	_udp_revoke,
	_udp_erred,
};
static _getdns_upstream_vmt       _tcp_vmt = {
	_nop_cleanup,		/* Handled by _address parent */
	_set_parent_port,
	_set_parent_tls_port,
	_nop_as_dict,		/* Handled by _address parent */
	_get_parent_name,
	_get_parent_addr,
	_tcp_get_transport_name,

	_nop_submit,
	_nop_revoke,
	_nop_erred,
};
static _getdns_upstream_vmt       _tls_vmt = {
	_nop_cleanup,		/* Handled by _address parent */
	_set_parent_port,
	_set_parent_tls_port,
	_nop_as_dict,		/* Handled by _address parent */
	_get_parent_name,
	_get_parent_addr,
	_tls_get_transport_name,

	_nop_submit,
	_nop_revoke,
	_nop_erred,
};
static _getdns_upstream_vmt       _doh_vmt = {
	_doh_cleanup,
	_doh_set_port,
	_doh_set_port,
	_nop_as_dict,		/* Handled by _doh_uri_parent */
	_doh_get_name,
	_doh_get_addr,
	_doh_get_transport_name,

	_nop_submit,
	_nop_revoke,
	_nop_erred,
};
