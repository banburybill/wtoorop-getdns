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

#ifndef USE_WINSOCK
#include <netdb.h>
#else
#include <iphlpapi.h>
typedef unsigned short in_port_t;
#endif

/* Functions for _getdns_upstreams 
 *****************************************************************************/
static void _upstream_nop(_getdns_upstream *self)
{ (void)self; }
static void _upstream_nop_uint32_t(_getdns_upstream *self, uint32_t n)
{ (void)self; (void)n; }
static getdns_return_t _upstream_nop_as_dict(_getdns_upstream *self, getdns_dict **dict_r)
{ (void)self; (void)dict_r; return GETDNS_RETURN_NOT_IMPLEMENTED; }

static _getdns_upstream_vmt _nop_upstream_vmt = {
	_upstream_nop,
	_upstream_nop_uint32_t,
	_upstream_nop_uint32_t,
	_upstream_nop_as_dict
};

void
_getdns_upstreams_init(_getdns_upstreams *upstreams, getdns_context *context)
{
	assert(upstreams);
	(void) memset(upstreams, 0, sizeof(_getdns_upstreams));
	upstreams->u.r.context = context;
	upstreams->u.u.vmt = &_nop_upstream_vmt;
}

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
	if (!(start = current = context->gups.u.r.children))
		; /* pass */
	else do {
		current->parent = &context->gups.u.u;
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
	if (!(start = current = upstreams->u.r.children))
		; /* pass */
	else do {
		current->vmt->cleanup(current);
		current = current->next;
	} while (current && current != start);

	upstreams->u.r.children = NULL;
}

getdns_return_t
_getdns_upstreams2list(_getdns_upstreams *upstreams, getdns_list **list_r)
{
	getdns_list *list = NULL;
	getdns_return_t r;
	getdns_dict *dict;
	_getdns_upstream *start, *current;

	assert(upstreams);

	if (!(start = current = upstreams->u.r.children))
		; /* pass */
	else do {
		if ((r = current->vmt->as_dict(current, &dict))) {
			if (list) getdns_list_destroy(list);
			return r;
		}
		if (!list
		&& !(list = getdns_list_create_with_context(upstreams->u.r.context)))
			return GETDNS_RETURN_MEMORY_ERROR;

		if ((r = _getdns_list_append_this_dict(list, dict))) {
			getdns_list_destroy(list);
			return r;
		}
		current = current->next;
	} while (current && current != start);

	if (!list
	&& !(list = getdns_list_create_with_context(upstreams->u.r.context)))
		return GETDNS_RETURN_MEMORY_ERROR;
	*list_r = list;
	return GETDNS_RETURN_GOOD;
}


/* Functions for _getdns_upstream data-structure traversal & maintenance 
 *****************************************************************************/

getdns_context *
_getdns_upstream_get_context(_getdns_upstream *upstream)
{
	if (!upstream)
		return NULL;
	while (upstream->parent)
		upstream = upstream->parent;
	return ((_getdns_upstreams *)upstream)->u.r.context;
}

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
	if (!(iter->current = upstreams->current[cap & 7])) {
		_getdns_upstream *current = upstreams->u.r.children;

		if (!current
		|| (!_upstream_cap_complies((cap & 7), current->may)
		   && !(current = _getdns_next_upstream( current
		                                       , cap & 7, NULL))))
			return NULL;
		iter->current = upstreams->current[cap & 7] = current;
	}
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


/* Address based upstreams
 *****************************************************************************/

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

static _getdns_upstream_vmt _default_upstream_vmt = {
	_upstream_nop,
	_set_parent_port,
	_set_parent_tls_port,
	_upstream_nop_as_dict
};

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
	up->super.vmt = &_default_upstream_vmt;
	up->super.may = CAP_MIGHT;
	up->to_retry = 1;
	up->back_off = 1;
}

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
	up->super.vmt = &_default_upstream_vmt;
	up->super.may = (CAP_MIGHT | CAP_STATEFUL);
	up->fd = -1;
	up->conn_backoff_interval = 1;
	(void) getdns_eventloop_event_init(&up->event, up, NULL, NULL, NULL);
	(void) getdns_eventloop_event_init(
	    &up->finished_event, up, NULL, NULL, NULL);
}

typedef struct _tls_upstream {
	_stateful_upstream super;
	
	uint16_t               tls_port;
        SSL*                   tls_obj;
        SSL_SESSION*           tls_session;
        getdns_tls_hs_state_t  tls_hs_state;
        getdns_auth_state_t    tls_auth_state;
        unsigned               tls_fallback_ok : 1;
        char                  *tls_cipher_list;
        char                  *tls_curves_list;
        /* Auth credentials*/
        char                   tls_auth_name[256];
        sha256_pin_t          *tls_pubkey_pinset;

	/* These are running totals or historical info */
	getdns_auth_state_t    best_tls_auth_state;
	getdns_auth_state_t    last_tls_auth_state;
} _tls_upstream;

static void
_tls_upstream_init(_tls_upstream *up)
{
	_stateful_upstream_init(&up->super);
	up->super.super.may |= CAP_ENCRYPTED;

	up->tls_port = 853;
	up->tls_hs_state = GETDNS_HS_NONE;
	up->tls_auth_name[0] = '\0';
	up->tls_auth_state = GETDNS_AUTH_NONE;
	up->last_tls_auth_state = GETDNS_AUTH_NONE;
	up->best_tls_auth_state = GETDNS_AUTH_NONE;
}

typedef struct _tsig_st {
	uint8_t          tsig_dname[256];
	size_t           tsig_dname_len;
	size_t           tsig_size;
	uint8_t          tsig_key[256];
	getdns_tsig_algo tsig_alg;
} _tsig_st;

typedef struct _address_upstream {
	_getdns_upstream         super;
	
	socklen_t                addr_len;
	struct sockaddr_storage  addr;
	char                     addr_str[INET6_ADDRSTRLEN];

	_stateless_upstream      udp;
	_stateful_upstream       tcp;
	_tls_upstream            tls;

	_tsig_st                 tsig;
} _address_upstream;

static void _address_upstream_cleanup(_getdns_upstream *to_cast)
{
	struct mem_funcs  *mfs;
	_address_upstream *self = (_address_upstream *)to_cast;

	assert(self);

	mfs = priv_getdns_context_mf(_getdns_upstream_get_context(to_cast));
	assert(mfs); /* invariant of data-structure */

	/* TODO: Complete upstream destruction */

	GETDNS_FREE(*mfs, self);
}

static void _address_upstream_set_port(_getdns_upstream *to_cast, uint32_t port)
{
	_address_upstream *self = (_address_upstream *)to_cast;
	assert(self);

	if (self->addr.ss_family == AF_INET)
		((struct sockaddr_in *)(&self->addr))->sin_port = htons(port);

	else if (self->addr.ss_family == AF_INET6)
		((struct sockaddr_in6 *)(&self->addr))->sin6_port = htons(port);
}

static void _address_upstream_set_tls_port(_getdns_upstream *to_cast, uint32_t port)
{
	_address_upstream *self = (_address_upstream *)to_cast;
	assert(self);

	self->tls.tls_port = port;
}

static getdns_return_t _address_upstream_as_dict(
    _getdns_upstream *to_cast, getdns_dict **dict_r)
{
	_address_upstream *self = (_address_upstream *)to_cast;
	getdns_dict *dict = NULL;
	getdns_return_t r = GETDNS_RETURN_GOOD;
	getdns_bindata bindata;
	char addr_str[1024], *b;
	uint16_t port;

	assert(self);

	if (!(dict = getdns_dict_create_with_context(_getdns_upstream_get_context(to_cast))))
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

static _getdns_upstream_vmt _address_upstream_vmt = {
	_address_upstream_cleanup,
	_address_upstream_set_port,
	_address_upstream_set_tls_port,
	_address_upstream_as_dict
};

getdns_return_t
_getdns_append_address_str_upstream(_getdns_upstream *parent,
    const char *addr_str, _getdns_upstream **new_upstream)
{
	struct mem_funcs  *mfs;
	_address_upstream *up;
	struct addrinfo    hints;
	struct addrinfo   *ai = NULL;
	int gai_r;

	assert(parent);
	assert(addr_str); /* contract for usage within library*/

	mfs = priv_getdns_context_mf(_getdns_upstream_get_context(parent));
	assert(mfs); /* invariant of data-structure */

	if (!(up = GETDNS_MALLOC(*mfs, _address_upstream)))
		return GETDNS_RETURN_MEMORY_ERROR;

	(void) memset(up, 0, sizeof(*up));
	up->super.parent             = parent;
	up->super.children           = &up->udp.super;
	up->super.vmt                = &_address_upstream_vmt;

	up->udp.super.parent         = &up->super;
	up->udp.super.children       = NULL;
	up->udp.super.next           = &up->tcp.super;

	up->tcp.super.parent         = &up->super;
	up->tcp.super.children       = NULL;
	up->tcp.super.next           = &up->tls.super.super;

	up->tls.super.super.parent   = &up->super;
	up->tls.super.super.children = NULL;
	up->tls.super.super.next     = &up->udp.super;

	_stateless_upstream_init(&up->udp);
	_stateful_upstream_init(&up->tcp);
	_tls_upstream_init(&up->tls);

	(void) strlcpy(up->addr_str, addr_str, sizeof(up->addr_str));
	(void) memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family    = AF_UNSPEC;      /* Allow IPv4 or IPv6 */
	hints.ai_flags     = AI_NUMERICHOST; /* No reverse name lookups */
	if ((gai_r = getaddrinfo(addr_str, "53", &hints, &ai))) {
		/* log("Could not convert %s to network address: \"%s\"\n",
		 * gai_strerror(gai_r));
		 */
		(void)gai_r;
		if (ai) freeaddrinfo(ai);
		GETDNS_FREE(*mfs, up);
		return GETDNS_RETURN_INVALID_PARAMETER;
	}
	if (!ai) {
		/* log("Could not convert %s to network address: \"%s\"\n") */
		GETDNS_FREE(*mfs, up);
		return GETDNS_RETURN_INVALID_PARAMETER;
	}
	up->addr_len = ai->ai_addrlen;
	(void) memcpy(&up->addr, ai->ai_addr, ai->ai_addrlen);
	up->addr.ss_family = ai->ai_family;
	up->tsig.tsig_alg = GETDNS_NO_TSIG;

	_upstream_append(parent, &up->super);

	if (new_upstream)
		*new_upstream = &up->super;
	return GETDNS_RETURN_GOOD;
}

