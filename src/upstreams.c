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
 * DISCLAIMED. IN NO EVENT SHALL NLnet Labs and/or Sinodun. BE LIABLE FOR ANY
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
#include <nghttp2/nghttp2.h>
#include <openssl/err.h>

#ifndef USE_WINSOCK
#include <netdb.h>
#else
#include <iphlpapi.h>
typedef unsigned short in_port_t;
#endif
#include <netinet/tcp.h>


#define STUB_TCP_RETRY           -6 /* Event has been rescheduled.
				     * The callback will be retried later.
				     * For submit (not a callback) this means:
				     *     "successfully scheduled"
				     */
#define STUB_TRY_AGAIN_LATER    -24 /* Only returned from submit.
				     * EMFILE, i.e. Out of OS resources
				     */
#define STUB_FATAL_ERROR       -125 /* Only returned from submit.
                                     * There is something wrong with the netreq
				     * Don't try other upstreams, but just fail
				     */
#define STUB_TRY_NEXT_UPSTREAM -126 /* Only returned from submit.
				     * This upstream is not ready (because it
				     * is temporarily disabled because of
				     * failure), try the next upstream.
				     */

#define TIMEOUT_TLS 2500

#define UP_LOG(UP, LEVEL, FMT, ...) \
    _getdns_log( &_up_context((UP))->log, GETDNS_LOG_SYS_STUB, (LEVEL) \
		 , "%s (%s) - " FMT "\n"			 \
		 , UPSTREAM_GET_NAME((UP))			 \
		 , UPSTREAM_GET_TRANSPORT_NAME((UP))		 \
		 , __VA_ARGS__ )

#define UP_EMERG(UP, ...) UP_LOG((UP), GETDNS_LOG_EMERG, __VA_ARGS__)
#define UP_ALERT(UP, ...) UP_LOG((UP), GETDNS_LOG_ALERT, __VA_ARGS__)
#define UP_CRIT(UP, ...) UP_LOG((UP), GETDNS_LOG_CRIT, __VA_ARGS__)
#define UP_ERR(UP, ...) UP_LOG((UP), GETDNS_LOG_ERR, __VA_ARGS__)
#define UP_WARN(UP, ...) UP_LOG((UP), GETDNS_LOG_WARNING, __VA_ARGS__)
#define UP_NOTICE(UP, ...) UP_LOG((UP), GETDNS_LOG_NOTICE, __VA_ARGS__)
#define UP_INFO(UP, ...) UP_LOG((UP), GETDNS_LOG_INFO, __VA_ARGS__)
#define UP_DEBUG(UP, ...) UP_LOG((UP), GETDNS_LOG_DEBUG, __VA_ARGS__)

static const upstream_caps all_trans_caps[] = {
	(CAP_STATELESS | CAP_UNENCRYPTED),
	(CAP_STATELESS |   CAP_ENCRYPTED),
	(CAP_STATEFUL  | CAP_UNENCRYPTED),
	(CAP_STATEFUL  |   CAP_ENCRYPTED),
	0
};

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



getdns_return_t
_getdns_submit_stub_request(getdns_network_req *netreq, uint64_t *now_ms);

static void _fallback_resubmit_netreq(getdns_network_req *netreq, uint64_t *now_ms)
{
	int r;
	DEBUG_STUB("%s %-35s: MSG: %p TYPE: %d\n", STUB_DEBUG_ENTRY, __FUNC__,
	           (void*)netreq, netreq->request_type);

	r = _getdns_submit_stub_request(netreq, now_ms);
	DEBUG_STUB("%s %-35s: MSG: %p TYPE: %d submit returned: %d\n", STUB_DEBUG_ENTRY, __FUNC__,
		   (void*)netreq, netreq->request_type, r);
	if (r) {
		/* TODO: Setting debug_end_time and calling 
		 * _getdns_check_dns_req_complete(netreq->owner)
		 * can be done from _getdns_netreq_change_state really.
		 * When state is changed to something finite.
		 */
		assert(!netreq->event.ev);
		_getdns_netreq_change_state(netreq, NET_REQ_ERRORED);
		netreq->debug_end_time = _getdns_get_time_as_uintt64();
		_getdns_check_dns_req_complete(netreq->owner);
	}
}

static void upstream_cleanup_children(_getdns_upstream *self)
{
	_getdns_upstream *start, *current;

	if (!self) return;

	/* Just call cleanup on one layer in the hierarchy.
	 * Individual upstreams are responsible for cleaning up their
	 * children themselfs.
	 */
	if (!(start = current = self->children))
		; /* pass */
	else do {
		_getdns_upstream *next = current->next;
		UPSTREAM_CLEANUP(current);
		current = next;
	} while (current && current != start);

	self->children = NULL;
}

/* Virtual Method Tables (initialized at end of file) */

static _getdns_upstream_vmt _upstreams_vmt;
static _getdns_upstream_vmt   _address_vmt;
static _getdns_upstream_vmt     _named_vmt;
static _getdns_upstream_vmt   _doh_uri_vmt;
static _getdns_upstream_vmt       _udp_vmt;
static _getdns_upstream_vmt       _tcp_vmt;
static _getdns_upstream_vmt       _tls_vmt;
static _getdns_upstream_vmt       _doh_vmt;

/* Functions for upstream_iter
 *****************************************************************************/
static void
upstream_set_visited(
    struct mem_funcs *mfs, upstream_iter *i, _getdns_upstream *u)
{
	size_t bit; 

	if (i->skip_sz == 0) {
		const size_t default_skip_sz = 1024;

		if (!(i->skip_bits = GETDNS_XMALLOC(
		    *mfs, uint8_t, default_skip_sz / 8)))
			return;
		(void) memset(i->skip_bits, 0, default_skip_sz / 8);
		i->skip_sz = default_skip_sz;
	}
	bit = (size_t)(bitmix64_hash((uint64_t)u) & (i->skip_sz - 1));
	i->skip_bits[bit >> 3] |= (1 << (bit & 7));
}

static void
upstream_unset_visited(upstream_iter *i, _getdns_upstream *u)
{
	size_t bit;

	if (!i->skip_sz)
		return;

	bit = (size_t)(bitmix64_hash((uint64_t)u) & (i->skip_sz - 1));
	i->skip_bits[bit >> 3] &= (0xFF ^ (1 << (bit & 7)));
}


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

_getdns_upstream *upstream_iter_next(upstream_iter *i)
{
	if (!i)
		return NULL;

	for ( i->current = _getdns_next_upstream(i->current, i->cap, i->stop_at)
	    ; i->current && upstream_visited(i, i->current)
	    ; i->current = _getdns_next_upstream(i->current, i->cap, i->stop_at))
		DEBUG_STUB("Skipping upstream (name: %s, trans: %s, caps: %x) for caps: %x\n"
		          , UPSTREAM_GET_NAME(i->current)
			  , UPSTREAM_GET_TRANSPORT_NAME(i->current)
			  , (int)i->current->may
			  , (int)i->cap)
		; /* pass */

	return i->current;
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



/* Functions for _getdns_upstreams 
 *****************************************************************************/

void
_getdns_upstreams_init(_getdns_upstreams *upstreams, getdns_context *context)
{
	assert(upstreams);
	(void) memset(upstreams, 0, sizeof(_getdns_upstreams));
	upstreams->context = context;
	upstreams->super.next = &upstreams->super;
	upstreams->super.vmt  = &_upstreams_vmt;
}

static inline _getdns_upstreams *_up_upstreams(_getdns_upstream *up)
{ if (!up) return NULL; while (up->parent) up = up->parent
; return up->vmt == &_upstreams_vmt ? (_getdns_upstreams *)up : NULL; }

void
_getdns_context_set_upstreams(getdns_context *context, _getdns_upstreams *upstreams)
{
	_getdns_upstream *start, *current;

	assert(context);
	assert(upstreams);

	context->gups = *upstreams;
	context->gups.super.next = &context->gups.super;
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
	DEBUG_STUB("%s %-35s: UPSTREAMS: %p\n", STUB_DEBUG_CLEANUP, __FUNC__, (void*)upstreams);
	upstream_cleanup_children(&upstreams->super);
}

getdns_return_t
_getdns_upstreams2list(const _getdns_upstreams *upstreams, getdns_list **list_r)
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

static void
register_processing(_getdns_upstream *up)
{
	_getdns_upstreams *ups = _up_upstreams(up);
	const upstream_caps *i;

	if (!ups)
		return;

	if (up->processing)
		return;

	for (i = all_trans_caps; *i; i++)
		if ((up->may & *i) == *i)
			ups->processing[*i] += 1;

	up->processing = 1;
}

static int
put_netreq_on_waiting_queue(getdns_network_req *netreq)
{
	_getdns_upstreams  *ups;
	getdns_netreq_fifo *fifo;

	if (!netreq || !(ups = _up_upstreams(netreq->gup.current)))
		return STUB_FATAL_ERROR;

	assert(netreq->next == NULL);
	fifo = &ups->waiting[netreq->gup.cap & CAP_TRANS];
	if (!fifo->head) {
		assert(!fifo->last);
		fifo->head = fifo->last = netreq;
	} else {
		assert(fifo->last);
		fifo->last->next = netreq;
		fifo->last = netreq;
	}
	return GETDNS_RETURN_GOOD;
}

/* Common actions that should be done for all netreq revocations */
static void
revoke_netreq(getdns_network_req *netreq)
{
	_getdns_upstreams  *ups;
	getdns_netreq_fifo *fifo;
	getdns_network_req *r, *prev_r;

	if (!netreq)
		return;

	/* Clear (timeout) events */
	if (netreq->event.ev)
		GETDNS_CLEAR_EVENT(netreq->owner->loop, &netreq->event);

	/* Remove netreq from the waiting queue */
	if (!(ups = _up_upstreams(netreq->gup.current)))
		return;

	fifo = &ups->waiting[netreq->gup.cap & CAP_TRANS];
	for ( r = fifo->head, prev_r = NULL
	    ; r ; prev_r = r, r = r->next) {
		if (r != netreq)
			continue;

		/* netreq found */
		if (prev_r)
			prev_r->next = r->next;
		else
			fifo->head = r->next;
		
		if (r == fifo->last) {
			/* If r was the last netreq,
			 * its next MUST be NULL
			 */
			assert(r->next == NULL);
			fifo->last = prev_r;
		}
		netreq->next = NULL;
		return;
	}
}

static void
netreq_timeout_cb(void *userarg)
{
	getdns_network_req *netreq = (getdns_network_req *)userarg;

	assert(netreq);
	if (!netreq->gup.current)
		revoke_netreq(netreq);
	else {
		UPSTREAM_REVOKE(netreq->gup.current, netreq);
		UPSTREAM_ERRED(netreq->gup.current);
	}
	_getdns_netreq_change_state(netreq, NET_REQ_TIMED_OUT);
	netreq->debug_end_time = _getdns_get_time_as_uintt64();
	_getdns_check_dns_req_complete(netreq->owner);
}

static void
deregister_processing(_getdns_upstream *up, upstream_caps cap)
{
	_getdns_upstreams *ups = _up_upstreams(up);
	const upstream_caps *i;
	uint64_t now_ms;

	if (!ups)
		return;

	DEBUG_STUB("Deregister upstream (name: %s, trans: %s, caps: %x,for processing: %d)\n"
	          , UPSTREAM_GET_NAME(up), UPSTREAM_GET_TRANSPORT_NAME(up)
                  , cap, up->processing);

	if (!up->processing)
		return;

	up->processing = 0;
	now_ms = 0;
	for (i = all_trans_caps; *i; i++) {

		DEBUG_STUB("cap: %x & *i: %x == %x\n", (int)cap, (int)*i, (int)(cap & *i));

		if ((cap & *i) != *i)
			continue;
		assert(ups->processing[*i] > 0);
		ups->processing[*i] -= 1;

		DEBUG_STUB("ups->processing[*i: %x] == %d\n", (int)*i, (int)ups->processing[*i]);
		/* TODO - show which upstreams are processing! */

		/* Resubmit waiting netreqs when there are no longer upstreams
		 * processing netreqs for this transport.
		 */
		while (ups->processing[*i] == 0) {
			getdns_network_req *netreq = ups->waiting[*i].head;

			DEBUG_STUB("Resubmitting: %p\n", (void *)netreq);

			if (!netreq)
				break;

			/* Revoke the netreq from the current upstream */
			if (netreq->gup.current)
				UPSTREAM_REVOKE(netreq->gup.current, netreq);
			else
				revoke_netreq(netreq);

			/* Revokation should have removed it from the queue
			 *
			 * assert(ups->waiting[*i].head != netreq)
			 */
			if (ups->waiting[*i].head != netreq)
				; /* pass */
			else if ((ups->waiting[*i].head = netreq->next))
				netreq->next = NULL;
			else
				ups->waiting[*i].last = NULL;

			_fallback_resubmit_netreq(netreq, &now_ms);
		}
	}
}

static inline getdns_context *_up_context(_getdns_upstream *upstream);
static void _upstream_erred(_getdns_upstream *self)
{
	assert(self);

	UP_NOTICE(self, "Shutdown because an error occurred\n", 0);
	deregister_processing(self, self->may);
}

static int 
send_from_waiting_queue(_getdns_upstream *self, uint64_t *now_ms)
{
	_getdns_upstreams   *ups;
	const upstream_caps *i;
	getdns_network_req  *prev_n;
	int r;

	DEBUG_STUB("%s %-35s\n", STUB_DEBUG_ENTRY, __FUNC__);

	if (!(ups = _up_upstreams(self)))
		return GETDNS_RETURN_GENERIC_ERROR;

	DEBUG_STUB("%s %-35s: UPS: %p\n", STUB_DEBUG_ENTRY, __FUNC__, (void *)ups);
	/* All transports for this upstream. */

	for (i = all_trans_caps; *i; i++) {
		getdns_network_req *netreq;

		if ((self->may & *i) != *i)
			continue;

		DEBUG_STUB("%s %-35s: suitable cap-transport found: %d\n",
		     STUB_DEBUG_ENTRY, __FUNC__, *i);
		prev_n = NULL;
		netreq = ups->waiting[*i].head;
		while (netreq) {
			DEBUG_STUB("%s %-35s: MSG: %p \n", STUB_DEBUG_ENTRY, __FUNC__, (void *)netreq);

			if (!_upstream_cap_complies(netreq->gup.cap, self->may)
			||  (  netreq->gup.current != self
			    && upstream_visited(&netreq->gup, self))
			||  (  r = UPSTREAM_SEND(self, netreq, now_ms))
			    == STUB_TRY_NEXT_UPSTREAM) {
				/* Netreq not complient with this upstream. */
				DEBUG_STUB("Skipping upstream (name: %s, trans: %s, caps: %x) for caps: %x\n"
					  , UPSTREAM_GET_NAME(netreq->gup.current)
					  , UPSTREAM_GET_TRANSPORT_NAME(netreq->gup.current)
					  , (int)netreq->gup.current->may
				  , (int)netreq->gup.cap);

				prev_n = netreq;
				netreq = netreq->next;
				continue;
			}
			DEBUG_STUB( "%s %-35s: MSG: %p, send returned: %d\n"
			          , STUB_DEBUG_ENTRY, __FUNC__, (void *)netreq, r);
			upstream_set_visited(
			    &netreq->owner->my_mf, &netreq->gup, self);
			if (r)
				return r;

			/* Netreq sucessfully submitted! */
			/* Set upstream iterator of this netreq to self */
			if (netreq->gup.current != self) {
				if (netreq->gup.current) {
					/* This upstream might be retried
					 * later.
					 */
					upstream_unset_visited(
					    &netreq->gup,
					     netreq->gup.current);
					/* We cannot revoke, because that
					 * might deregister things which
					 * have been registered by the
					 * earlier call to send.
					 */
				}
				netreq->gup.current = self;
				if (!netreq->gup.stop_at)
					netreq->gup.stop_at = self;
			}
			/* Remove netreq from waiting queue */
			if (ups->waiting[*i].last == netreq)
				ups->waiting[*i].last = prev_n;

			if (!prev_n && ups->waiting[*i].head == netreq) {
				ups->waiting[*i].head = netreq->next;
				netreq->next = NULL;
				netreq = ups->waiting[*i].head;

			} else if (prev_n && prev_n->next == netreq) {
				prev_n->next = netreq->next;
				netreq->next = NULL;
				netreq = prev_n->next;
			}
		}
	}
	return GETDNS_RETURN_GOOD;
}


/* functions for _getdns_upstream data-structure traversal & maintenance 
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

/* Address based upstreams
 *****************************************************************************/

typedef struct _stateless_upstream {
	_getdns_upstream super;

	int              to_retry; /* (initialized to 1) */
	int              back_off; /* (initialized to 1) */
	size_t           n_responses;
	size_t           n_timeouts;
	_edns_cookie_st  cookie;
} _stateless_upstream;

static void
_stateless_upstream_init(_stateless_upstream *up)
{
	assert(up);
	up->super.vmt = &_upstreams_vmt;
	up->super.may = CAP_MIGHT | CAP_STATELESS | CAP_UNENCRYPTED;
	up->super.processing = 0;
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

	unsigned int            connected : 1;

	int                     fd;
	getdns_eventloop_event  event;
	getdns_eventloop       *loop;
	
	getdns_tcp_state        tcp;
	_edns_cookie_st         cookie;

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
	_getdns_rbtree_t        netreq_by_id;

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


static int rb_intptr_cmp(const void *a, const void *b)
{ return a == b ? 0 : ((intptr_t)b < (intptr_t)b) ? -1 : 1; }

static void
_stateful_upstream_init(_stateful_upstream *up)
{
	assert(up);
	up->super.vmt = &_upstreams_vmt;
	up->super.may = CAP_MIGHT | CAP_STATEFUL | CAP_UNENCRYPTED;
	up->super.processing = 0;
	up->connected = 0;
	up->fd = -1;
	up->conn_backoff_interval = 1;
	(void) getdns_eventloop_event_init(&up->event, up, NULL, NULL, NULL);
	(void) getdns_eventloop_event_init(
	    &up->finished_event, up, NULL, NULL, NULL);
	_getdns_rbtree_init(&up->netreq_by_id, rb_intptr_cmp);
}

static inline _stateful_upstream *as_stateful_up(_getdns_upstream *up)
{ return up && (  up->vmt == &_tcp_vmt
               || up->vmt == &_tls_vmt
               || up->vmt == &_doh_vmt ) ? (_stateful_upstream *)up : NULL; }

static void _stateful_revoke(_getdns_upstream *self_up, getdns_network_req *netreq)
{
	// _stateful_upstream *self = as_stateful_up(self_up);
	(void)self_up;
	DEBUG_STUB("%s %-35s: MSG: %p\n", STUB_DEBUG_CLEANUP, __FUNC__, (void*)netreq);

	if (netreq->id_registered)
		(void) _getdns_rbtree_delete(
		    netreq->id_registered, netreq->node.key);
	revoke_netreq(netreq);
}

static void
_tcp_upstream_init(_stateful_upstream *up)
{
	assert(up);
	_stateful_upstream_init(up);
	up->super.vmt = &_tcp_vmt;
}

static int
tcp_connect(_stateful_upstream *self)
{
	int fd = -1;
	socklen_t addr_len;
	const struct sockaddr *addr = UPSTREAM_GET_ADDR(&self->super, &addr_len);

	DEBUG_STUB("%s %-35s: Creating TCP connection:      %p\n", STUB_DEBUG_SETUP, 
	           __FUNC__, (void*)self);

	fd = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1)
		return -1;
	DEBUG_STUB("SOCKET %d is inet: %d, is inet6: %d, fd: %d\n", addr->sa_family,
	    addr->sa_family == AF_INET,
	    addr->sa_family == AF_INET6,
	    fd);

	_getdns_sock_nonblock(fd);
	/* Note that error detection is different with TFO. Since the handshake
	   doesn't start till the sendto() lack of connection is often delayed until
	   then or even the subsequent event depending on the error and platform.*/
#ifdef USE_TCP_FASTOPEN
	/* Leave the connect to the later call to sendto() if using TCP*/
	if (self->super.vmt == &_tcp_vmt)
		return fd;

#elif USE_OSX_TCP_FASTOPEN
	sa_endpoints_t endpoints;
	endpoints.sae_srcif = 0;
	endpoints.sae_srcaddr = NULL;
	endpoints.sae_srcaddrlen = 0;
	endpoints.sae_dstaddr = addr;
	endpoints.sae_dstaddrlen = addr_len;
	if (connectx(fd, &endpoints, SAE_ASSOCID_ANY,
	             CONNECT_DATA_IDEMPOTENT | CONNECT_RESUME_ON_READ_WRITE,
	             NULL, 0, NULL, NULL) == 0) {
		return fd;
	}
	if (_getdns_socketerror() == _getdns_EINPROGRESS ||
	    _getdns_socketerror() == _getdns_EWOULDBLOCK)
		return fd;
#endif
	char buffer[INET6_ADDRSTRLEN] = "";
	int gni_r = getnameinfo(addr,addr_len,buffer,sizeof(buffer),
		    0,0,NI_NUMERICHOST);
	DEBUG_STUB("CONNECT FD %d to %s, port: %d, gni_r: %d\n", fd, buffer,
			(int)ntohs(((struct sockaddr_in *)addr)->sin_port), gni_r);

	if (connect(fd, addr, addr_len) == -1) {
		DEBUG_STUB("Connect returned: %s\n", _getdns_strerror(errno));
		if (_getdns_socketerror() == _getdns_EINPROGRESS ||
		    _getdns_socketerror() == _getdns_EWOULDBLOCK)
			return fd;
		_getdns_closesocket(fd);
		return -1;
	}
	return fd;
}

static int
tcp_connected(_stateful_upstream *upstream) {
	int error = 0;
	socklen_t len = (socklen_t)sizeof(error);

	DEBUG_STUB("%s %-35s: FD:  %d \n", STUB_DEBUG_SETUP_TLS, 
	             __FUNC__, upstream->fd);

	if (upstream->fd == -1) {
		if ((upstream->fd = tcp_connect(upstream)) < 0)
			return GETDNS_RETURN_IO_ERROR;
	}

	getsockopt(upstream->fd, SOL_SOCKET, SO_ERROR, (void*)&error, &len);
	if (_getdns_error_wants_retry(error))
		return STUB_TCP_RETRY;

	else if (error != 0) {
		return GETDNS_RETURN_IO_ERROR;
	}
	if (upstream->super.vmt == &_tcp_vmt &&
	    upstream->queries_sent == 0) {
		upstream->conn_state = GETDNS_CONN_OPEN;
		upstream->conn_completed++;
	}
	return GETDNS_RETURN_GOOD;
}

static void _tcp_erred(_getdns_upstream *self_up)
{
	_stateful_upstream *self = as_stateful_up(self_up);

	assert(self);

	if (self->event.ev) {
		GETDNS_CLEAR_EVENT(self->loop, &self->event);
	}
	if (self->fd >= 0) {
		_getdns_closesocket(self->fd);
		self->fd = -1;
	}
	_upstream_erred(self_up);
}

typedef struct _tls_upstream {
	_stateful_upstream super;

	socklen_t               addr_len;
	struct sockaddr_storage addr;

	/* Settings */
        char                   *tls_cipher_list;
        char                   *tls_curves_list;
        char                    tls_auth_name[256];
        sha256_pin_t           *tls_pubkey_pinset;

	/* State */
        _getdns_tls_connection *tls_obj;
        _getdns_tls_session    *tls_session;
        getdns_tls_hs_state_t   tls_hs_state;
        getdns_auth_state_t     tls_auth_state;
        unsigned                tls_fallback_ok : 1;
	getdns_auth_state_t     best_tls_auth_state;
	getdns_auth_state_t     last_tls_auth_state;
} _tls_upstream;

static void
_tls_upstream_init(_tls_upstream *up, const struct addrinfo *ai, uint16_t port)
{
	_stateful_upstream_init(&up->super);
	up->super.super.vmt = &_tls_vmt;
	up->super.super.may = CAP_MIGHT | CAP_STATEFUL | CAP_ENCRYPTED;

	up->addr_len = ai->ai_addrlen;
	(void) memcpy(&up->addr, ai->ai_addr, ai->ai_addrlen);
	switch ((up->addr.ss_family = ai->ai_family)) {
	case AF_INET:
		((struct sockaddr_in *)(&up->addr))->sin_port = htons(port);
		break;
	case AF_INET6:
		((struct sockaddr_in6 *)(&up->addr))->sin6_port = htons(port);
	default:
		break;
	};

	/* Settings */
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
{ return up && (  up->vmt == &_tls_vmt
               || up->vmt == &_doh_vmt ) ? (_tls_upstream *)up : NULL; }

static void _tls_cleanup(_getdns_upstream *self_up)
{
	struct mem_funcs *mfs;
	_tls_upstream *self = as_tls_up(self_up);

	if (!self)
		return;
	mfs = priv_getdns_context_mf(_up_context(self_up));
	if (self->tls_session) {
		_getdns_tls_session_free(mfs, self->tls_session);
		self->tls_session = NULL;
	}
	if (self->tls_obj) {
		_getdns_tls_connection_free(mfs, self->tls_obj);
		self->tls_obj = NULL;
	}
}

static void _tls_set_port(_getdns_upstream *self_up, uint32_t port)
{
	_tls_upstream *self = as_tls_up(self_up);

	if (!self)
		; /* pass */

	else if (self->addr.ss_family == AF_INET)
		((struct sockaddr_in *)(&self->addr))->sin_port = htons(port);

	else if (self->addr.ss_family == AF_INET6)
		((struct sockaddr_in6 *)(&self->addr))->sin6_port = htons(port);
}

static const struct sockaddr *
_tls_get_addr(_getdns_upstream *self_up, socklen_t *addrlen)
{
	_tls_upstream *self = as_tls_up(self_up);

	if (self) {
		if (addrlen) *addrlen = self->addr_len;
		return (struct sockaddr *)&self->addr;
	}
	return NULL;
}

static int tls_do_handshake(_tls_upstream *upstream, uint64_t *now_ms);

static void
tls_hs_timeout_cb(void *arg)
{
	_stateful_upstream *self = (_stateful_upstream *)arg;

	if (!arg) return;
	GETDNS_CLEAR_EVENT(self->loop, &self->event);
	UPSTREAM_ERRED(&self->super);
}

static void
tls_handshake_cb(void *arg)
{
	_tls_upstream *upstream = (_tls_upstream *)arg;
	uint64_t now_ms = 0;
	int r;

	DEBUG_STUB("%s %-35s: FD:  %d\n", STUB_DEBUG_SETUP_TLS, 
	             __FUNC__, upstream->super.fd);

	r = tls_do_handshake(upstream, &now_ms);

	DEBUG_STUB( "%s %-35s: FD:  %d, tls_do_handshake returned %d\n"
	          , STUB_DEBUG_SETUP_TLS, __FUNC__, upstream->super.fd, r);

	if (r == GETDNS_RETURN_GOOD || r == STUB_TCP_RETRY)
		return;

	UPSTREAM_ERRED(&upstream->super.super);
}

static int
tls_do_handshake(_tls_upstream *upstream, uint64_t *now_ms)
{
	struct mem_funcs* mfs;
	int r;
	DEBUG_STUB("%s %-35s: FD:  %d\n", STUB_DEBUG_SETUP_TLS, 
	             __FUNC__, upstream->super.fd);

	if ((r = _getdns_tls_connection_do_handshake(upstream->tls_obj)) != GETDNS_RETURN_GOOD) {
		switch (r) {
		case GETDNS_RETURN_TLS_WANT_WRITE:
			DEBUG_STUB("WANT HS WRITE\n");
			GETDNS_CLEAR_EVENT(
			    upstream->super.loop, &upstream->super.event);
			upstream->super.event.read_cb  = NULL;
			upstream->super.event.write_cb = tls_handshake_cb;
			upstream->super.event.timeout_cb = tls_hs_timeout_cb;
			GETDNS_SCHEDULE_EVENT(upstream->super.loop,
			    upstream->super.fd, TIMEOUT_TLS, &upstream->super.event);
			upstream->tls_hs_state = GETDNS_HS_WRITE;
			return STUB_TCP_RETRY;

		case GETDNS_RETURN_TLS_WANT_READ:
			DEBUG_STUB("WANT HS READ\n");
			GETDNS_CLEAR_EVENT(
			    upstream->super.loop, &upstream->super.event);
			upstream->super.event.read_cb  = tls_handshake_cb;
			upstream->super.event.write_cb = NULL;
			GETDNS_SCHEDULE_EVENT(upstream->super.loop,
			    upstream->super.fd, TIMEOUT_TLS, &upstream->super.event);
			upstream->super.event.timeout_cb = tls_hs_timeout_cb;
			upstream->tls_hs_state = GETDNS_HS_READ;
			return STUB_TCP_RETRY;
		default:
			DEBUG_STUB("%s %-35s: FD:  %d Handshake failed %d (%s) (%s)\n", 
				    STUB_DEBUG_SETUP_TLS, __FUNC__,
				    upstream->super.fd, want,
			            ERR_error_string(ERR_get_error(), NULL),
				    _getdns_strerror(errno)
				    );
			return GETDNS_RETURN_IO_ERROR;
		}
	}
	/* TODO: auth status string */
	DEBUG_STUB("%s %-35s: FD:  %d Handshake succeeded with auth state %s. Session is %s.\n", 
	    STUB_DEBUG_SETUP_TLS, __FUNC__, upstream->super.fd, "<UNKNOWN>",
	    _getdns_tls_connection_is_session_reused(upstream->tls_obj) ?"re-used":"new");

	upstream->tls_hs_state = GETDNS_HS_DONE;
	upstream->super.conn_state = GETDNS_CONN_OPEN;
	upstream->super.conn_completed++;
	mfs = priv_getdns_context_mf(_up_context(&upstream->super.super));
	if (upstream->tls_session != NULL)
		_getdns_tls_session_free(mfs, upstream->tls_session);
	upstream->tls_session = _getdns_tls_connection_get_session(mfs, upstream->tls_obj);
	/* Reset timeout on success*/

	GETDNS_CLEAR_EVENT(upstream->super.loop, &upstream->super.event);

	return UPSTREAM_RUN(&upstream->super.super, now_ms);

}

static int
tls_connected(_tls_upstream *upstream, getdns_eventloop *loop, uint64_t *now_ms)
{
	int r;
	getdns_context *context = _up_context(&upstream->super.super);
	_getdns_tls_context *tls_ctx;

	DEBUG_STUB("%s %-35s: FD:  %d \n", STUB_DEBUG_SETUP_TLS, 
	             __FUNC__, upstream->super.fd);

	/* Already have a TLS connection*/
	if (upstream->tls_hs_state == GETDNS_HS_DONE)
		return GETDNS_RETURN_GOOD;

	/* Already tried and failed, so let the fallback code take care of things
	 * TODO: Check when we should retry.
	 */
	if (upstream->tls_hs_state == GETDNS_HS_FAILED)
		return STUB_TRY_NEXT_UPSTREAM;

	if (upstream->super.loop != loop) {
		upstream->super.loop = loop;
		upstream->super.is_sync_loop =
		    context && &context->sync_eventloop.loop == loop;
	}

	/* Lets make sure the TCP connection is up before we try a handshake 
	 * STUB_TCP_RETRY is okay, if we're not yet handshaking
	 */
	if ((r = tcp_connected(&upstream->super)) &&
	    (r != STUB_TCP_RETRY || upstream->tls_hs_state != GETDNS_HS_NONE))
		return r;

	if (!(tls_ctx = UPSTREAM_SETUP_TLS_CTX(&upstream->super.super)))
		return GETDNS_RETURN_IO_ERROR;

	if (!upstream->tls_obj) {
		DEBUG_STUB("%s %-35s: FD:  %d tls_obj setup\n",
		    STUB_DEBUG_SETUP_TLS, __FUNC__, upstream->super.fd);

		if (!(upstream->tls_obj = _getdns_tls_connection_new(&context->my_mf, tls_ctx, upstream->super.fd, &context->log))) {
			return GETDNS_RETURN_IO_ERROR;
		}
	}
	return tls_do_handshake(upstream, now_ms);
}

static _getdns_tls_context *_tls_setup_tls_ctx(_getdns_upstream *self_up)
{
	getdns_context *context;

	if (!(context = _up_context(self_up)))
		return NULL;
	return context->tls_ctx;
}

static int
_tls_submit(_getdns_upstream *self_up,
    getdns_network_req *netreq, uint64_t *now_ms)
{
	_tls_upstream *self = as_tls_up(self_up);
	int r;

	DEBUG_STUB("%s(%s - %s) %-35s: MSG: %p TYPE: %d\n"
	          , STUB_DEBUG_ENTRY, UPSTREAM_GET_NAME(self_up)
		  , UPSTREAM_GET_TRANSPORT_NAME(self_up), __FUNC__
		  , (void*)netreq, netreq->request_type);

	if (!self)
		return STUB_TRY_NEXT_UPSTREAM;

	if (!netreq)
		return UPSTREAM_START(self_up, now_ms);

	assert(netreq->gup.current == self_up);
	if ((r = tls_connected(self, netreq->owner->loop, now_ms)) &&
	    r != STUB_TCP_RETRY)
		return r;

	if (self->super.connected) {
		assert(!netreq->event.ev);

		if (!(r = UPSTREAM_SEND(self_up, netreq, now_ms)))
			r = GETDNS_SCHEDULE_EVENT(netreq->owner->loop, -1,
			    _getdns_ms_until_expiry2(netreq->owner->expires, now_ms),
			    getdns_eventloop_event_init(&netreq->event, netreq, NULL, NULL, netreq_timeout_cb));
		return r;
	}
	/* Not connected, so connecting... put on waiting queue */
	if ((r = GETDNS_SCHEDULE_EVENT(netreq->owner->loop, -1,
	    _getdns_ms_until_expiry2(netreq->owner->expires, now_ms),
	    getdns_eventloop_event_init(&netreq->event, netreq, NULL, NULL, netreq_timeout_cb))))
		return r;

	register_processing(self_up);
	return put_netreq_on_waiting_queue(netreq);
}

static int _tls_start(_getdns_upstream *self_up, uint64_t *now_ms)
{
	int r;
	_tls_upstream *self = as_tls_up(self_up);

	DEBUG_STUB("%s %-35s\n", STUB_DEBUG_ENTRY, __FUNC__);

	if (!self->super.loop)
		return GETDNS_RETURN_IO_ERROR;

	else if ((r = tls_connected(self, self->super.loop, now_ms)))
		return r;

	else if (self->super.connected)
		return send_from_waiting_queue(self_up, now_ms);
	else
		return GETDNS_RETURN_GOOD;
}

static int
_tls_run(_getdns_upstream *self_up, uint64_t *now_ms)
{
	_tls_upstream *self = as_tls_up(self_up);

	self->super.connected = 1;
	UP_INFO(self_up, "Connected", 0);
	return send_from_waiting_queue(self_up, now_ms);
}

static void _tls_erred(_getdns_upstream *self_up)
{
	struct mem_funcs *mfs;
	_tls_upstream *self = as_tls_up(self_up);

	assert(self);

	mfs = priv_getdns_context_mf(_up_context(self_up));
	_getdns_tls_connection_free(mfs, self->tls_obj);
	self->tls_obj = NULL;
	self->tls_hs_state = GETDNS_HS_NONE;
	self->tls_auth_state = GETDNS_AUTH_NONE;
	/* Don't cleanup tls_session, because of TLS session resumption */

	_tcp_erred(self_up);
}

typedef struct _doh_upstream {
	_tls_upstream super;
	
	/* settings */
	char                     uri[4096];
	nghttp2_session         *session;
	unsigned int             erred: 1;

	_tsig_st                 tsig;

	/* state */
	_getdns_tls_context     *tls_ctx;
} _doh_upstream;

static inline _doh_upstream *as_doh_up(_getdns_upstream *up)
{ return up && up->vmt == &_doh_vmt ? (_doh_upstream *)up : NULL; }

static void _doh_cleanup(_getdns_upstream *self_up)
{
	struct mem_funcs  *mfs;
	_doh_upstream *self = as_doh_up(self_up);

	DEBUG_STUB("%s %-35s: MSG: %p\n", STUB_DEBUG_CLEANUP, __FUNC__, (void*)self_up);

	if (!self)
		return;
	if (self->session) {
		nghttp2_session_del(self->session);
		self->session = NULL;
	}
	_tls_cleanup(self_up);
	mfs = priv_getdns_context_mf(_up_context(self_up));
	if (self->tls_ctx) {
		_getdns_tls_context_free(mfs, self->tls_ctx);
		self->tls_ctx = NULL;
	}
	GETDNS_FREE(*mfs, self_up);
}

static const char *
_doh_get_name(_getdns_upstream *self_up)
{
	_doh_upstream *self = as_doh_up(self_up);
	return self ? self->uri : NULL;
}

static _getdns_tls_context *
_doh_setup_tls_ctx(_getdns_upstream *self_up)
{
	getdns_context *context = _up_context(self_up);
	_doh_upstream *self;

	if (!(self = as_doh_up(self_up)))
		return NULL;

	DEBUG_STUB("%s %-35s: FD:  %d DoH tls_ctx setup\n",
	    STUB_DEBUG_SETUP_TLS, __FUNC__, self->super.super.fd);

	if ( !self->tls_ctx &&
	     !(self->tls_ctx = _getdns_tls_context_new(&context->my_mf, &context->log)))
		return NULL;

	if ( _getdns_tls_context_set_options(self->tls_ctx, GETDNS_TLS_CONTEXT_OPT_NO_COMPRESSION | GETDNS_TLS_CONTEXT_OPT_NO_SESSION_RESUMPTION_ON_RENEGOTIATION) != GETDNS_RETURN_GOOD ||
	     _getdns_tls_context_set_min_max_tls_version(self->tls_ctx, GETDNS_TLS1_2, 0) != GETDNS_RETURN_GOOD ||
	     _getdns_tls_context_set_alpn_protos(self->tls_ctx, GETDNS_TLS_ALPN_HTTP2_TLS) != GETDNS_RETURN_GOOD )
		return NULL;
	return self->tls_ctx;
}

static void
_doh_write_cb(void *arg)
{
	_doh_upstream *self = (_doh_upstream *)arg;
	int rv;

	DEBUG_STUB("%s %-35s: FD:  %d\n", STUB_DEBUG_WRITE, __FUNC__, self->super.super.fd);

	self->erred = 0;
	if ((rv = nghttp2_session_send(self->session))) {
		UP_ERR(&self->super.super.super, "Could not send: \"%s\"",nghttp2_strerror(rv));
		UPSTREAM_ERRED(&self->super.super.super);
	}
	if (self->erred)
		UPSTREAM_ERRED(&self->super.super.super);
}

static void
_doh_read_cb(void *arg)
{
	_doh_upstream *self = (_doh_upstream *)arg;
	int rv;

	DEBUG_STUB("%s %-35s: FD:  %d\n", STUB_DEBUG_READ, __FUNC__, self->super.super.fd);

	self->erred = 0;
	if ((rv = nghttp2_session_recv(self->session))) {
		UP_ERR(&self->super.super.super, "Could not recv: \"%s\"",nghttp2_strerror(rv));
		UPSTREAM_ERRED(&self->super.super.super);
		return;
	}
	if (self->erred) {
		UPSTREAM_ERRED(&self->super.super.super);
		return;
	}
	if ((rv = nghttp2_session_send(self->session))) {
		UP_ERR(&self->super.super.super, "Could not send: \"%s\"",nghttp2_strerror(rv));
		UPSTREAM_ERRED(&self->super.super.super);
	}
	if (self->erred)
		UPSTREAM_ERRED(&self->super.super.super);
}

static ssize_t
_doh_reschedule_on_SSL_error(_stateful_upstream *self, _getdns_tls_connection* conn, int err)
{
	(void) conn;
	switch (err) {
	case GETDNS_RETURN_TLS_WANT_READ:
		if (self->event.ev)
			GETDNS_CLEAR_EVENT(self->loop, &self->event);
		GETDNS_SCHEDULE_EVENT(
		    self->loop, self->fd, TIMEOUT_FOREVER,
		    getdns_eventloop_event_init(&self->event, self,
		    _doh_read_cb, NULL, NULL));
		DEBUG_STUB("%s %-35s: FD: %d WANT READ\n", STUB_DEBUG_SCHEDULE, __FUNC__, self->fd);
		return NGHTTP2_ERR_WOULDBLOCK;

	case GETDNS_RETURN_TLS_WANT_WRITE:
		if (self->event.ev)
			GETDNS_CLEAR_EVENT(self->loop, &self->event);
		GETDNS_SCHEDULE_EVENT(
		    self->loop, self->fd, TIMEOUT_FOREVER,
		    getdns_eventloop_event_init(&self->event, self,
		    _doh_read_cb, _doh_write_cb, NULL));
		DEBUG_STUB("%s %-35s: FD: %d WANT WRITE\n", STUB_DEBUG_SCHEDULE, __FUNC__, self->fd);
		return NGHTTP2_ERR_WOULDBLOCK;

	default:
		UP_WARN( &self->super, "SSL error" , 0);
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}
}

static ssize_t
send_callback(nghttp2_session *session, const uint8_t *data, size_t length,
    int flags,  void *user_data)
{
	_doh_upstream *self_doh = as_doh_up((_getdns_upstream *)user_data);
	_stateful_upstream *self;
	_getdns_tls_connection* conn;
	size_t written;
	getdns_return_t res;

	(void)session;
	(void)flags;

	if (!self_doh)
		return NGHTTP2_ERR_CALLBACK_FAILURE;

	self = &self_doh->super.super;
	if (!(conn = self_doh->super.tls_obj))
		return 0;

	DEBUG_STUB("%s %-35s: FD: %d to write: %zu\n", STUB_DEBUG_WRITE, __FUNC__, self->fd, length);
	res = _getdns_tls_connection_write(conn, data, length, &written);
	if (res == GETDNS_RETURN_GOOD) {
		DEBUG_STUB("%s %-35s: FD: %d written: %d\n", STUB_DEBUG_WRITE, __FUNC__, self->fd, written);
		return (ssize_t)written;
	}
	return _doh_reschedule_on_SSL_error(self, conn, res);
}

static ssize_t
recv_callback(nghttp2_session *session, uint8_t *buf, size_t length,
    int flags,  void *user_data)
{
	_doh_upstream *self_doh = as_doh_up((_getdns_upstream *)user_data);
	_stateful_upstream *self;
	_getdns_tls_connection* conn;
	size_t read;
	getdns_return_t res;


	(void)session;
	(void)flags;

	if (!self_doh)
		return NGHTTP2_ERR_CALLBACK_FAILURE;

	self = &self_doh->super.super;
	if (!(conn = self_doh->super.tls_obj))
		return 0;

	DEBUG_STUB("%s %-35s: FD: %d to read: %zu\n", STUB_DEBUG_READ, __FUNC__, self->fd, length);
	res = _getdns_tls_connection_read(conn, buf, length, &read);
	if (res == GETDNS_RETURN_GOOD) {
		DEBUG_STUB("%s %-35s: FD: %d read: %d\n", STUB_DEBUG_READ, __FUNC__, self->fd, read);
		return (ssize_t)read;
	}
	return _doh_reschedule_on_SSL_error(self, conn, read);
}

static int
on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
    int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
{
	_stateful_upstream *self = (_stateful_upstream *)user_data;
	getdns_network_req *netreq;
	intptr_t stream_id_intptr = (intptr_t)stream_id;
	(void)session;

	assert(data);
	assert(self);

	DEBUG_STUB("%s %-35s: self: %p, flags: %d, stream_id: %d, length: %zu\n", STUB_DEBUG_READ, __FUNC__, (void *)self, (int)flags, stream_id, len);

	netreq = (getdns_network_req *)_getdns_rbtree_search(
	    &self->netreq_by_id, (void *)stream_id_intptr);
	if (! netreq) /* Netreq might have been canceled (so okay!) */
		return 0;

	/* Consistency paranoia */
	if (netreq->id_registered != &self->netreq_by_id) {
		if (netreq->id_registered)
			(void) _getdns_rbtree_delete(
			    netreq->id_registered, netreq->node.key);
		netreq->id_registered = &self->netreq_by_id;
	}
	/* Length should have been previously announced (with the
	 * "content-length:" header) and we should have a sufficient
	 * buffer ready.
	 */
	if (!netreq->content_len || !netreq->response_ptr
	||  (netreq->response_ptr - netreq->response) + len
	   > netreq->content_len) {
		uint64_t now_ms = 0;
		DEBUG_STUB("ERROR in DATA CHUNK!!\n");
		UPSTREAM_REVOKE(&self->super, netreq);
		_fallback_resubmit_netreq(netreq, &now_ms);
		return -1;
	}
	(void) memcpy(netreq->response_ptr, data, len);
	netreq->response_ptr += len;
	if ((netreq->response_ptr - netreq->response) ==
	    (ssize_t)netreq->content_len) {
		UPSTREAM_REVOKE(&self->super, netreq);
		netreq->response_len = netreq->content_len;
		netreq->debug_end_time = _getdns_get_time_as_uintt64();
		_getdns_netreq_change_state(netreq, NET_REQ_FINISHED);
		_getdns_check_dns_req_complete(netreq->owner);
	}
	return 0;
}

static int
on_header_callback (nghttp2_session *session, const nghttp2_frame *frame,
    const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen,
    uint8_t flags, void *user_data)
{
	_stateful_upstream *self = (_stateful_upstream *)user_data;
	getdns_network_req *netreq;
	intptr_t stream_id_intptr;
	char digits[10];
	char *endptr;
	(void)session;
	(void)flags;

	if (frame->hd.type != NGHTTP2_HEADERS
	||  frame->headers.cat != NGHTTP2_HCAT_RESPONSE)
		return 0;

       	stream_id_intptr = (intptr_t)frame->hd.stream_id;
	netreq = (getdns_network_req *)_getdns_rbtree_search(
	    &self->netreq_by_id, (void *)stream_id_intptr);
	if (! netreq) /* Netreq might have been canceled (so okay!) */
		return 0;

	/* Consistency paranoia */
	if (netreq->id_registered != &self->netreq_by_id) {
		if (netreq->id_registered)
			(void) _getdns_rbtree_delete(
			    netreq->id_registered, netreq->node.key);
		netreq->id_registered = &self->netreq_by_id;
	}

	fprintf(stderr, "incoming header: ");
	fwrite(name, 1, namelen, stderr);
	fprintf(stderr, ": ");
	fwrite(value, 1, valuelen, stderr);
	fprintf(stderr, "\n");
	if (namelen == 7 && !strncasecmp((const char *)name, ":status", 7)) {
		if (valuelen != 3 || strncmp((const char *)value, "200", 3)) {
			uint64_t now_ms =0;

			UP_WARN( &self->super
			       , "Did not receive 200 status in HTTP/2 reply"
				 ", rescheduling\n", 0);
			UPSTREAM_REVOKE(&self->super, netreq);
			_fallback_resubmit_netreq(netreq, &now_ms);
		}
		return 0;
	} else if (namelen == 12 &&
	    !strncasecmp((const char *)name, "content-type", 12)) {
		if (valuelen != 23 ||
		    strncasecmp((const char *)value,
		    "application/dns-message", 23)) {
			uint64_t now_ms =0;

			UP_WARN( &self->super
			       , "Content type of HTTP/2 reply was not "
				 "application/dns-message "
				 ", rescheduling\n", 0);
			UPSTREAM_REVOKE(&self->super, netreq);
			_fallback_resubmit_netreq(netreq, &now_ms);
		}
		return 0;
	} else if (namelen != 14 ||
	    strncasecmp((const char *)name, "content-length", 14))
		return 0;

	if (valuelen >= sizeof(digits)) {
		uint64_t now_ms =0;

		UP_WARN( &self->super
		       , "HTTP/2 Content-length header value was too "
			 "large\n", 0);
		UPSTREAM_REVOKE(&self->super, netreq);
		_fallback_resubmit_netreq(netreq, &now_ms);
		return 0;
	}
	(void) memcpy(digits, value, valuelen);
	digits[valuelen] = 0;
	netreq->content_len = strtol(digits, &endptr, 10);
	if (*endptr != '\0' || endptr == digits) {
		uint64_t now_ms =0;

		UP_WARN( &self->super
		       , "HTTP/2 Content-length header had an illegal "
			 "value: \"%s\"\n", digits);
		UPSTREAM_REVOKE(&self->super, netreq);
		_fallback_resubmit_netreq(netreq, &now_ms);
		return 0;
	}
	if (netreq->content_len >
	    (netreq->wire_data_sz - (netreq->response - netreq->wire_data))) {
		UP_ERR( &self->super
		      , "Need to allocate a new response buffer", 0);
		assert(0);
		return 0;
	}
	netreq->response_ptr = netreq->response;

	return 0;
}

static int
_doh_run(_getdns_upstream *self_up, uint64_t *now_ms)
{
	_doh_upstream *self = as_doh_up(self_up);
	_getdns_tls_alpn_proto_t proto;
	int val = 1;
	nghttp2_session_callbacks *callbacks;

	if (!self)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (_getdns_tls_connection_get_alpn_proto(self->super.tls_obj, &proto) != GETDNS_RETURN_GOOD || proto != GETDNS_TLS_ALPN_HTTP2_TLS) {
		UP_ERR(self_up, "h2 is not negotiaded", 0);
		self->erred = 1;
		return GETDNS_RETURN_IO_ERROR;
	}
	setsockopt(self->super.super.fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));

	if (nghttp2_session_callbacks_new(&callbacks))
		return GETDNS_RETURN_MEMORY_ERROR;

	nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
	nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);
	nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);
	/*
	nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
	nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
	nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, on_begin_headers_callback);
	*/
	if (nghttp2_session_client_new(&self->session, callbacks, self)) {
		nghttp2_session_callbacks_del(callbacks);
		return GETDNS_RETURN_MEMORY_ERROR;
	}
	nghttp2_session_callbacks_del(callbacks);

	return _tls_run(self_up, now_ms);
}

static void _doh_erred(_getdns_upstream *self_up)
{
	_doh_upstream *self = as_doh_up(self_up);

	assert(self);

	if (self->session) {
		nghttp2_session_del(self->session);
		self->session = NULL;
	}
	/* Don't cleanup tls_ctx */

	_tls_erred(self_up);
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

	DEBUG_STUB("%s %-35s: MSG: %p\n", STUB_DEBUG_CLEANUP, __FUNC__, (void*)self_up);

	if ((mfs = priv_getdns_context_mf(_up_context(self_up)))) {
		/* TODO: complete address destruction
		 * like deregister transport upstreams
		 * for processing waiting queues
		 */
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
		((struct sockaddr_in6 *)(&self->addr))->sin6_port =
		    htons(port);
}

static void _address_set_tls_port(_getdns_upstream *self_up, uint32_t port)
{
	_address_upstream *self = as_address_up(self_up);

	if (!self)
	       ;
	else if (self->tls.addr.ss_family == AF_INET)
		((struct sockaddr_in *)(&self->tls.addr))->sin_port =
		    htons(port);

	else if (self->tls.addr.ss_family == AF_INET6)
		((struct sockaddr_in6 *)(&self->tls.addr))->sin6_port =
		    htons(port);
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
	if (!r) {
		switch (self->tls.addr.ss_family) {
		case AF_INET : port = ntohs(((struct sockaddr_in *)
		                             (&self->addr))->sin_port);
		               break;
		case AF_INET6: port = ntohs(((struct sockaddr_in6 *)
                                             (&self->tls.addr))->sin6_port);
		               break;
		default      : port = 853;
		               break;
		}
		if (port != 853)
			r = getdns_dict_set_int(dict, "tls_port", port);
	};
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

static int
_address_start(_getdns_upstream *self, uint64_t *now_ms)
{
	_getdns_upstream *start, *child;
	int r = GETDNS_RETURN_GOOD;

	if (!self)
		return GETDNS_RETURN_INVALID_PARAMETER;

	DEBUG_STUB("Start upstream %p for %s with transport %s\n",
	    (void *)self, UPSTREAM_GET_NAME(self), UPSTREAM_GET_TRANSPORT_NAME(self));

	start = child = self->children;
	while (child) {
		int c_r;
		
		if ((c_r = UPSTREAM_START(child, now_ms)) && !r)
			r = c_r;

		if ((child = child->next) == start)
			break;
	}
	return r;
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
	_tls_upstream_init(&up->tls, ai, 853);

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
	getdns_network_req      *req_a;
	getdns_network_req      *req_aaaa;
	unsigned int             done_a   : 1;
	unsigned int             done_aaaa: 1;
} _named_upstream;

static inline _named_upstream *as_named_up(_getdns_upstream *up)
{ return up && (  up->vmt == &_named_vmt
               || up->vmt == &_doh_uri_vmt ) ? (_named_upstream *)up : NULL; }

typedef struct _doh_uri_upstream {
	_named_upstream super;
	
	/* Settings */
	char            uri[4096];
	char           *path;
} _doh_uri_upstream;

static inline _doh_uri_upstream *as_doh_uri_up(_getdns_upstream *up)
{ return up && up->vmt == &_doh_uri_vmt ? (_doh_uri_upstream *)up : NULL; }


static ssize_t
post_data_read_callback (nghttp2_session *session, int32_t stream_id,
    uint8_t *buf, size_t length, uint32_t *data_flags,
    nghttp2_data_source *source, void *user_data)
{
	getdns_network_req *netreq = (getdns_network_req *)source->ptr;
	_doh_upstream *self = (_doh_upstream *)user_data;
	(void)self;
	(void)session;

	DEBUG_STUB("POST(stream_id: %d, buf: %p, length: %zu, *flags: %u, data to send: %ld)\n"
	          , stream_id, buf, length, *data_flags, (netreq->response - netreq->query));

	(void) memcpy(buf, netreq->query, netreq->response - netreq->query);
	*data_flags |= NGHTTP2_DATA_FLAG_EOF;
	return (ssize_t)(netreq->response - netreq->query);
}

#define MAKE_NV(NAME, VALUE, VALUELEN) { (uint8_t *)NAME, (uint8_t *)VALUE, \
    sizeof(NAME) - 1, VALUELEN, NGHTTP2_NV_FLAG_NONE }

#define MAKE_NV2(NAME, VALUE) { (uint8_t *)NAME, (uint8_t *)VALUE, \
    sizeof(NAME) - 1, sizeof(VALUE) - 1, NGHTTP2_NV_FLAG_NONE }

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

static int _doh_send(_getdns_upstream *self_up,
    getdns_network_req *netreq, uint64_t *now_ms)
{
	_doh_upstream      *self;
	_doh_uri_upstream  *parent;
	_stateful_upstream *self_st;
	ssize_t pkt_len;
	char content_length[10] = "-1";
	nghttp2_nv hdrs[6] =
	    { MAKE_NV2(":method"       , "POST")
	    , MAKE_NV2(":scheme"       , "https")
	    , MAKE_NV2(":authority"    , "hdrs[2].value & hdrs[2].valuelen")
	    , MAKE_NV2(":path"         , "hdrs[3].value & hdrs[3].valuelen")
	    , MAKE_NV2("content-type"  , "application/dns-message")
	    , MAKE_NV2("content-length", content_length)
	    };
	nghttp2_data_provider data_prd;
	intptr_t stream_id_intptr;
	int rv;
	(void)now_ms;

	assert((self = as_doh_up(self_up)));
	assert((parent = as_doh_uri_up(self_up->parent)));

	if ((pkt_len = _prepare_netreq_packet_for_send(
	    &self->super.super.super, netreq,
	    &self->super.super.cookie, NULL)) < 0) /* TODO: pass TSIG */
		return GETDNS_RETURN_GENERIC_ERROR;

	hdrs[2].value    =  (uint8_t *)parent->super.name;
	hdrs[2].valuelen =      strlen(parent->super.name);
	hdrs[3].value    = (uint8_t *)(parent->path - 1);
	hdrs[3].valuelen =      strlen(parent->path - 1);
	hdrs[5].valuelen = snprintf( content_length, sizeof(content_length)
	                           , "%d", (int)pkt_len );

	size_t i;
	for (i = 0; i < ARRLEN(hdrs); i++) {
		fprintf(stderr, "header: ");
		fwrite(hdrs[i].name, 1, hdrs[i].namelen, stderr);
		fprintf(stderr, ": ");
		fwrite(hdrs[i].value, 1, hdrs[i].valuelen, stderr);
		fprintf(stderr, "\n");
	}
	data_prd.source.ptr = netreq;
	data_prd.read_callback = post_data_read_callback;
	if ((netreq->stream_id = nghttp2_submit_request(self->session, NULL,
	    hdrs, ARRLEN(hdrs), &data_prd, NULL)) < 0)
		return GETDNS_RETURN_IO_ERROR;

	if ((rv = nghttp2_session_send(self->session) != 0)) {
		UP_ERR(self_up, "Could not send: \"%s\"",nghttp2_strerror(rv));
		return GETDNS_RETURN_IO_ERROR;
	}
	self_st = &self->super.super;
	stream_id_intptr = (intptr_t)netreq->stream_id;
	netreq->node.key = (void *)stream_id_intptr;
	if (!_getdns_rbtree_insert(&self_st->netreq_by_id, &netreq->node)) {
		/* Revoke the netreq on the tree */
		return GETDNS_RETURN_GENERIC_ERROR;
	}
	netreq->id_registered = &self_st->netreq_by_id;
	if (!self_st->event.ev) {
		GETDNS_SCHEDULE_EVENT(
		    self_st->loop, self_st->fd, TIMEOUT_FOREVER,
		    getdns_eventloop_event_init(&self_st->event, self,
		    _doh_read_cb, NULL, NULL));
		DEBUG_STUB("%s %-35s: FD: %d schedule read\n", STUB_DEBUG_SCHEDULE, __FUNC__, self_st->fd);
	}
	return GETDNS_RETURN_GOOD;
}



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
	_tls_upstream_init(&up->super, ai, 443);
	up->super.super.super.vmt = &_doh_vmt;
	(void)snprintf(up->uri, sizeof(up->uri),
	    "https://%s/%s", addr_str, parent->path);
	up->session = NULL;
	if (parent->super.req_a)
		up->super.super.loop = parent->super.req_a->owner->loop;
	else if (parent->super.req_aaaa)
		up->super.super.loop = parent->super.req_aaaa->owner->loop;

	up->tsig.tsig_alg = GETDNS_NO_TSIG;

	_upstream_append(parent_up, &up->super.super.super);
	if (new_upstream)
		*new_upstream = &up->super.super.super;
	return GETDNS_RETURN_GOOD;
}

static getdns_return_t
_named_equip(_getdns_upstream *self_up, int af, const uint8_t *addr,
    _getdns_upstream **new_upstream)
{
	_named_upstream *self = as_named_up(self_up);
	char             a_buf[40];
	getdns_return_t  r;

	if (!self)
		return GETDNS_RETURN_INVALID_PARAMETER;
   
	if (!inet_ntop(af, addr, a_buf, sizeof(a_buf))) {
		/* TODO: Log reason (family not supported, or no space) */
		return GETDNS_RETURN_INVALID_PARAMETER;
	}
	DEBUG_STUB("Address lookup (for named upstream): %s\n", a_buf);

	if ((r = _getdns_append_upstream(self_up, a_buf, new_upstream)))
		/* TODO: Log something? */
		return r;

	if (self->port != 53)
		(*new_upstream)->vmt->set_port(*new_upstream, self->port);

	if (self->tls_port != 853)
		(*new_upstream)->vmt->set_tls_port(*new_upstream, self->tls_port);

	return GETDNS_RETURN_GOOD;
}

static getdns_return_t
_doh_uri_equip(_getdns_upstream *self_up, int af, const uint8_t *addr,
    _getdns_upstream **new_upstream)
{
	_doh_uri_upstream *self = as_doh_uri_up(self_up);
	char               a_buf[40];
	struct addrinfo    hints;
	struct addrinfo   *ai = NULL;
	getdns_return_t     r;

	if (!self)
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (!inet_ntop(af, addr, a_buf, sizeof(a_buf))) {
		/* TODO: Log reason (family not supported, or no space) */
		return GETDNS_RETURN_INVALID_PARAMETER;
	}
	DEBUG_STUB("Address lookup (for DoH): %s\n", a_buf);

	(void) memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family    = AF_UNSPEC;      /* IPv4 or IPv6 */
	hints.ai_flags     = AI_NUMERICHOST; /* No reverse lookups */

	if (getaddrinfo(a_buf, "443", &hints, &ai))
		/* TODO: log getaddrinfo error */
		return GETDNS_RETURN_GENERIC_ERROR;

	else if ((r = _getdns_append_doh_upstream(
	    self_up, ai, a_buf, new_upstream)))
		; /* TODO: do something with append doh_upstream error? */

	else if (self->super.port != 443)
		(*new_upstream)->vmt->set_port(*new_upstream, self->super.port);

	if (ai) freeaddrinfo(ai);
	return r;
}

static void
_named_address_answer_cb(_named_upstream *self, getdns_network_req **netreq,
    size_t addrlen, int af)
{
	_getdns_rrset_spc    rrset_spc;
	_getdns_rrset       *rrset;
	_getdns_rrtype_iter  rr_spc;
	_getdns_rrtype_iter *rr;
	upstream_caps        had_caps;
	uint64_t             now_ms = 0;

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

		if (UPSTREAM_EQUIP(
		    &self->super, af, rr->rr_i.rr_type + 10 , &new_upstream))
			; /* TODO: log equip error? */
		else
			UPSTREAM_START(new_upstream, &now_ms);
	}
	_getdns_context_cancel_request((*netreq)->owner);
	*netreq = NULL; /* netreq is either &self->req_a or &self->req_aaaa */

	if (!self->done_a || self->req_a || !self->done_aaaa || self->req_aaaa)
		return;

	/* If all lookups are done, remove capabilities,
	 * so no new queries will be queued.
	 * ( we might reconsider this and clean capabilities on first
	 *   scheduled query, so that the next will potentially
	 *   be scheduled against an already CAP_CONNECTED upstream )
	 */
	had_caps = self->super.may;
	self->super.may  = 0;

	/* Nothing more to expect from this upstream.  (i.e. it's address
	 * children should start picking up requests from the waiting queues)
	 */
	deregister_processing(&self->super, had_caps);
}

static void _named_a_answer_cb(getdns_dns_req *dnsreq)
{
	_named_upstream     *self = (_named_upstream *)dnsreq->user_pointer;

	if (!self) return;
	_named_address_answer_cb(self, &self->req_a, 4, AF_INET);
}

static void _named_aaaa_answer_cb(getdns_dns_req *dnsreq)
{
	_named_upstream     *self = (_named_upstream *)dnsreq->user_pointer;

	if (!self) return;
	_named_address_answer_cb(self, &self->req_aaaa, 16, AF_INET6);
}

static int _named_submit(
    _getdns_upstream *self_up, getdns_network_req *netreq, uint64_t *now_ms)
{
	getdns_return_t r;
	getdns_context *context = NULL;
	_named_upstream *self = as_named_up(self_up);
	int resolving;

	(void)now_ms;

	DEBUG_STUB("%s %-35s: MSG: %p TYPE: %d\n", STUB_DEBUG_ENTRY, __FUNC__,
	           (void*)netreq, netreq->request_type);

	if (!self)
		return STUB_TRY_NEXT_UPSTREAM;

	resolving = self->req_a || self->req_aaaa;

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
		/* We are resolving now.  If we weren't already on function
		 * entry, register as processing for our transports.
		 */
		if (!resolving)
			register_processing(self_up);

		if (!netreq->event.ev &&
		    GETDNS_SCHEDULE_EVENT(netreq->owner->loop, -1,
		    _getdns_ms_until_expiry2(netreq->owner->expires, now_ms),
		     getdns_eventloop_event_init(
		    &netreq->event, netreq, NULL, NULL, netreq_timeout_cb)))
			return STUB_FATAL_ERROR;

		return put_netreq_on_waiting_queue(netreq);
	}
	return STUB_TRY_NEXT_UPSTREAM;
}

static void _named_revoke(
    _getdns_upstream *self_up, getdns_network_req *netreq)
{
	//_named_upstream *self = as_named_up(self_up);
	(void)self_up;
	DEBUG_STUB("%s %-35s: MSG: %p\n", STUB_DEBUG_CLEANUP, __FUNC__, (void*)netreq);

	revoke_netreq(netreq);

	/* No registration except for the waiting queues in upstreams
	 * which are already handled by revoke_netreq
	 */
}

static void _named_erred(_getdns_upstream *self_up)
{
	/* _named_upstream *self = as_named_up(self_up); */
	(void)(self_up);

	/* Erred is irrelevant, since this upstreams deregisters itself after 
	 * scheduling lookups for the name by setting it's capabilities to 0.
	 */
}

void
_named_cleanup(_getdns_upstream *self)
{
	struct mem_funcs *mfs;

	DEBUG_STUB("%s %-35s: MSG: %p\n", STUB_DEBUG_CLEANUP, __FUNC__, (void*)self);
	upstream_cleanup_children(self);
	if ((mfs = priv_getdns_context_mf(_up_context(self)))) {
		/* TODO: complete destruction
		 * Cancel running address lookups etc.
		 */
		GETDNS_FREE(*mfs, self);
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
	up->super.may = (CAP_MIGHT     & ((CAP_RESOLVED)
	                                  ^ 0xFFFF))
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
	up->super.port = 443;
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

static void
_udp_revoke(_getdns_upstream *self_up, getdns_network_req *netreq)
{
	DEBUG_STUB("%s %-35s: MSG: %p\n", STUB_DEBUG_CLEANUP, __FUNC__, (void*)netreq);
	(void)self_up;

	revoke_netreq(netreq);

	/* Close socket */
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
			_getdns_log(&_up_context(&up->super)->log,
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
	    _udp_read_cb, NULL, netreq_timeout_cb));

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

static int
_udp_send(_getdns_upstream *self_up,
    getdns_network_req *netreq, uint64_t *now_ms)
{
	_stateless_upstream *self = as_udp_up(self_up);
	socklen_t              addrlen;
	const struct sockaddr *addr;

	DEBUG_STUB("%s %-35s: MSG: %p TYPE: %d\n", STUB_DEBUG_ENTRY, __FUNC__,
	           (void*)netreq, (netreq ? netreq->request_type : -1));

	if (!self)
		return STUB_TRY_NEXT_UPSTREAM;

	if (!netreq)
		return send_from_waiting_queue(self_up, now_ms);

	if (  self->to_retry <= 0 &&
	    ++self->to_retry <= 0)
		return STUB_TRY_NEXT_UPSTREAM;

	if (!(addr = UPSTREAM_GET_ADDR(&self->super, &addrlen)))
		return GETDNS_RETURN_GENERIC_ERROR;

	netreq->fd = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (netreq->fd < 0)
		return _getdns_resource_depletion()
		     ? STUB_TRY_AGAIN_LATER
		     : (int)GETDNS_RETURN_IO_ERROR;

	_getdns_sock_nonblock(netreq->fd);
	if (netreq->owner->write_udp_immediately)
		return _udp_write(self, netreq, now_ms);

	/* Clear (timeout) events */
	if (netreq->event.ev)
		GETDNS_CLEAR_EVENT(netreq->owner->loop, &netreq->event);

	return GETDNS_SCHEDULE_EVENT(netreq->owner->loop, netreq->fd,
	    _getdns_ms_until_expiry2(netreq->owner->expires, now_ms),
	     getdns_eventloop_event_init(&netreq->event, netreq,
		     NULL, _udp_write_cb, netreq_timeout_cb));
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
		int r = UPSTREAM_SUBMIT(up, netreq, now_ms);

		if (r != STUB_TRY_AGAIN_LATER)
			upstream_set_visited(
			    &netreq->owner->my_mf, &netreq->gup, up);
		switch (r) {
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
			continue; /* Try next upstream */

		case STUB_FATAL_ERROR:
			/* Fatal error scheduling timeout for the netreq */
			return GETDNS_RETURN_IO_ERROR;

		default:
			/* Not submitted, so no revoke needed */
			UPSTREAM_ERRED(up);
			continue; /* Try next upstream */
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
; DEBUG_STUB("Submit netreq %p with transport %s on upstream %p for %s\n", (void *)netreq, UPSTREAM_GET_TRANSPORT_NAME(self), (void *)self, UPSTREAM_GET_NAME(self))
; return GETDNS_RETURN_NOT_IMPLEMENTED; }
static int _nop_start(_getdns_upstream *self, uint64_t *now_ms)
{ (void)self; (void)now_ms
; DEBUG_STUB("Start upstream %p for %s with transport %s\n", (void *)self, UPSTREAM_GET_NAME(self), UPSTREAM_GET_TRANSPORT_NAME(self))
; return GETDNS_RETURN_NOT_IMPLEMENTED; }

static void _nop_revoke(_getdns_upstream *self, getdns_network_req *netreq)
{ (void)self; (void)netreq; ; DEBUG_STUB("Revoke netreq %p with transport %s on upstream %p for %s\n", (void *)netreq, UPSTREAM_GET_TRANSPORT_NAME(self), (void *)self, UPSTREAM_GET_NAME(self)); }
static void _nop_erred(_getdns_upstream *self)
{ (void)self; DEBUG_STUB("Upstream %p for %s with transport %s erred\n", (void *)self, UPSTREAM_GET_NAME(self), UPSTREAM_GET_TRANSPORT_NAME(self)); }

static int _nop_send(
    _getdns_upstream *self, getdns_network_req *netreq, uint64_t *now_ms)
{ (void)self; (void)netreq; (void)now_ms
; DEBUG_STUB("Send netreq %p with transport %s on upstream %p for %s\n", (void *)netreq, UPSTREAM_GET_TRANSPORT_NAME(self), (void *)self, UPSTREAM_GET_NAME(self))
; return GETDNS_RETURN_NOT_IMPLEMENTED; }
static int _nop_run(_getdns_upstream *self, uint64_t *now_ms)
{ (void)self; (void)now_ms;
; DEBUG_STUB("Start_processing upstream %p for %s with transport %s\n", (void *)self, UPSTREAM_GET_NAME(self), UPSTREAM_GET_TRANSPORT_NAME(self));
; return GETDNS_RETURN_NOT_IMPLEMENTED; }

static getdns_return_t _nop_equip(_getdns_upstream *self_up,
    int af, const uint8_t *addr, _getdns_upstream **new_upstream)
{ (void)self_up; (void)new_upstream; (void)af; (void)addr;
; assert(0); return GETDNS_RETURN_NOT_IMPLEMENTED; }

static _getdns_tls_context *_nop_setup_tls_ctx(_getdns_upstream *self)
{ (void)self; return NULL; }


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

static _getdns_upstream_vmt _upstreams_vmt = {
	_nop_cleanup,
	_nop_uint32_t,
	_nop_uint32_t,
	_nop_as_dict,
	_nop_get_name,
	_nop_get_addr,
	_nop_get_transport_name,

	_nop_submit,
	_nop_send,
	_nop_start,
	_nop_run,
	_nop_revoke,
	_nop_erred,

	_nop_equip,
	_nop_setup_tls_ctx
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
	_nop_send,
	_address_start,
	_nop_run,
	_nop_revoke,
	_nop_erred,

	_nop_equip,
	_nop_setup_tls_ctx
};
static _getdns_upstream_vmt _named_vmt = {
	_named_cleanup,
	_named_set_port,
	_named_set_tls_port,
	_named_as_dict,
	_named_get_name,
	_nop_get_addr,
	_nop_get_transport_name,

	_named_submit,
	_nop_send,
	_nop_start,
	_nop_run,
	_named_revoke,
	_named_erred,

	_named_equip,
	_nop_setup_tls_ctx
};
static _getdns_upstream_vmt _doh_uri_vmt = {
	_named_cleanup,
	_named_set_port,
	_named_set_port,
	_doh_uri_as_dict,
	_doh_uri_get_name,
	_nop_get_addr,
	_doh_get_transport_name,

	_named_submit,
	_nop_send,
	_nop_start,
	_nop_run,
	_named_revoke,
	_named_erred,

	_doh_uri_equip,
	_nop_setup_tls_ctx
};
static _getdns_upstream_vmt       _udp_vmt = {
	_nop_cleanup,		/* Handled by _address parent */
	_set_parent_port,
	_set_parent_tls_port,
	_nop_as_dict,		/* Handled by _address parent */
	_get_parent_name,
	_get_parent_addr,
	_udp_get_transport_name,

	_udp_send,
	_udp_send,
	send_from_waiting_queue,
	send_from_waiting_queue,
	_udp_revoke,
	_udp_erred,

	_nop_equip,
	_nop_setup_tls_ctx
};
static _getdns_upstream_vmt  _tcp_vmt = {
	_nop_cleanup,		/* Handled by _address parent */
	_set_parent_port,
	_set_parent_tls_port,
	_nop_as_dict,		/* Handled by _address parent */
	_get_parent_name,
	_get_parent_addr,
	_tcp_get_transport_name,

	_nop_submit,
	_nop_send,
	_nop_start,
	_nop_run,
	_stateful_revoke,
	_tcp_erred,

	_nop_equip,
	_nop_setup_tls_ctx
};
static _getdns_upstream_vmt _tls_vmt = {
	_tls_cleanup,
	_tls_set_port,
	_tls_set_port,
	_nop_as_dict,		/* Handled by _address parent */
	_get_parent_name,
	_tls_get_addr,
	_tls_get_transport_name,

	_tls_submit,
	_nop_send,
	_tls_start,
	_tls_run,
	_stateful_revoke,
	_tls_erred,

	_nop_equip,
	_tls_setup_tls_ctx
};
static _getdns_upstream_vmt _doh_vmt = {
	_doh_cleanup,
	_tls_set_port,
	_tls_set_port,
	_nop_as_dict,		/* Handled by _doh_uri_parent */
	_doh_get_name,
	_tls_get_addr,
	_doh_get_transport_name,

	_tls_submit,
	_doh_send,
	_tls_start,
	_doh_run,
	_stateful_revoke,
	_doh_erred,

	_nop_equip,
	_doh_setup_tls_ctx
};

