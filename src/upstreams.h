/**
 * \file upstreams.h
 * @brief Functions for managing upstreams
 */

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
#ifndef _GETDNS_UPSTREAMS_H_
#define _GETDNS_UPSTREAMS_H_

#include "getdns/getdns.h"
#include "config.h"

typedef struct getdns_network_req getdns_network_req;
struct mem_funcs;
typedef uint16_t upstream_caps;

#define CAP_STATELESS         0x0001
#define CAP_STATEFUL          0x0002
#define CAP_UNENCRYPTED       0x0004
#define CAP_ENCRYPTED         0x0008
#define CAP_TRANS             0x000f

#define CAP_AUTHENTICATED     0x0010 /* Not initialized with CAP_MIGHT */
#define CAP_MIGHT             0xFFE0
#define CAP_RESOLVED          0x0020 /* Upstream has IP address */

#define CAP_OOOR              0x0080
#define CAP_QNAME_MIN         0x0100

#define CAP_EDNS0             0x0200
#define CAP_KEEPALIVE         0x0400
#define CAP_PADDING           0x0800

#define CAP_DNSSEC_VALIDATION 0x1000
#define CAP_DNSSEC_SIGS       0x2000
#define CAP_DNSSEC_NSECS      0x4000
#define CAP_DNSSEC_WILDCARDS  0x8000

/*
 * typedef struct upstream_caps {
 * 	unsigned int stateful         : 1;
 * 	unsigned int encrypted        : 1;
 * 	unsigned int authenticated    : 1;
 * 
 * 	unsigned int qname_min        : 1;
 * 	unsigned int ooor             : 1;
 * 	unsigned int edns0            : 1;
 * 	unsigned int keepalive        : 1;
 * 	unsigned int padding          : 1;
 * 	unsigned int dnssec_validation: 1;
 * 	unsigned int dnssec           : 2; // 1 = positive (i.e. sigs)
 * 					   // 2 = negative (i.e. nsecs)
 * 					   // 3 = wildcard (i.e. bind bug )
 * } upstream_caps;
 */

static inline int _upstream_cap_complies(upstream_caps req, upstream_caps cap)
{ return (cap & req) == req; /* req bits must be set in cap */ }


/*---------------------------------------------------------------------------*/


#define UPSTREAM_CLEANUP(UP)            ((UP)->vmt->cleanup((UP)))
#define UPSTREAM_AS_DICT(UP, DICT_R)    ((UP)->vmt->as_dict((UP),(DICT_R)))
#define UPSTREAM_GET_NAME(UP)           ((UP)->vmt->get_name((UP)))
#define UPSTREAM_GET_ADDR(UP, LEN_R)    ((UP)->vmt->get_addr((UP),(LEN_R)))
#define UPSTREAM_GET_TRANSPORT_NAME(UP) ((UP)->vmt->get_transport_name((UP)))

#define UPSTREAM_SUBMIT(UP, NETREQ, MS) ((UP)->vmt->submit((UP),(NETREQ),(MS)))
#define UPSTREAM_SEND(UP, NETREQ, MS)   ((UP)->vmt->send((UP),(NETREQ),(MS)))
#define UPSTREAM_START(UP, MS)          ((UP)->vmt->start((UP),(MS)))
#define UPSTREAM_RUN(UP, MS)            ((UP)->vmt->run((UP),(MS)))
#define UPSTREAM_REVOKE(UP, NETREQ)     ((UP)->vmt->revoke((UP),(NETREQ)))
#define UPSTREAM_ERRED(UP)              ((UP)->vmt->erred((UP)))

#define UPSTREAM_EQUIP(UP, AF, IP, NEW_UP) \
    ((UP)->vmt->equip((UP),(AF),(IP),(NEW_UP)))
#define UPSTREAM_SETUP_TLS_CTX(UP)      ((UP)->vmt->setup_tls_ctx((UP)))



typedef struct _getdns_upstream _getdns_upstream;
typedef const struct _getdns_upstream_vmt {
	void            (*cleanup)(_getdns_upstream *self);
	void            (*set_port)(_getdns_upstream *self, uint32_t);
	void            (*set_tls_port)(_getdns_upstream *self, uint32_t);

	getdns_return_t (*as_dict)(_getdns_upstream *s, getdns_dict **dict_r);

	const char *    (*get_name)(_getdns_upstream *self);
	const struct sockaddr *
	                (*get_addr)(_getdns_upstream *self, socklen_t *len);
	const char *    (*get_transport_name)(_getdns_upstream *self);

	/* submit() is called by _getdns_submit_stub_request()
	 * submit() returns:
	 *   - GETDNS_RETURN_GOOD    : When the request could be successfully
	 *                             scheduled.  All registration needed for
	 *                             the netreq with this upstream has been
	 *                             done.
	 *
	 *                             The netreq must be deregisted from this
	 *                             upstream with a call to revoke().
         *
	 *   - STUB_TRY_NEXT_UPSTREAM: When this upstream is backed off and not
	 *                             ready to schedule the request.
	 *
	 *   - STUB_TRY_AGAIN_LATER  : When system resourced are deplated and
	 *                             another attempt can be made when
	 *                             resources become available again.
	 *
	 *   - GETDNS_RETURN_IO_ERROR: or any other error.  This will cause 
	 *                             erred() to be called for this upstream,
	 *                             which does the failure management, such
	 *                             as backing off this upstream if needed.
	 *
	 * When upstreams need initialisation (for example connecting
	 * stateful transports), but the request might be handled with this
	 * upstream.  It is put on a waiting queue.
	 */
	int (*submit)(_getdns_upstream *s,
	    getdns_network_req *netreq, uint64_t *now_ms);

	/* send() is like submit but assumes that the upstream is connected
	 * send() will handle waiting queues (and will not put netreqs on them)
	 * send() will not be called directly by _getdns_submit_stub_request().
	 *        but only via submit() and or start() and run()
	 *
	 * For stateless upstreams send() should be equivalent to submit().
	 */
	int (*send)(_getdns_upstream *s,
	    getdns_network_req *netreq, uint64_t *now_ms);

	/* start() is called after a upstream is constructed and positioned in
	 * the "upstreams" data-structure.  start() is for example run with
	 * address upstreams that were constructed and inserted in the data-
	 * structure as a result of address lookups (with named upstreams).
	 *
	 * When start is called for an upstream that needs initialisation,
	 * such as connecting stateful transport, that initialisation is
	 * initiated.
	 *
	 * For stateless upstreams start() should be equivalent to run().
	 */
	int (*start)(_getdns_upstream *s, uint64_t *now_ms);

	/* run() will take netreqs from the (for the upstream's transport)
	 * waiting queue, and feed them to send().
	 */
	int (*run)(_getdns_upstream *s, uint64_t *now_ms);

	/* revoke() deregisters the netreq with the upstream.
	 * This may involve:
	 *   - Removing the netreq from waiting queues.
	 *   - Removing the netreq from data structures within the upstream.
	 *   - Closing sockets and freeing other resources.
	 *   - Clearing or rescheduling I/O events.
	 */
	void (*revoke)(_getdns_upstream *s, getdns_network_req *netreq);

	/* erred() is called when the upstream failed (for a request).
	 * The number of failures are tracked, and the upstream is registered
	 * to be backed off if needed.  A backed off upstream will result in
	 * STUB_TRY_NEXT_UPSTREAM returned from submit().
	 */
	void (*erred)(_getdns_upstream *s);


	/* Methods for descendant classes:
	 */
	/* For named_upstream and the descendant doh_uri_upstream */
	getdns_return_t (*equip)(_getdns_upstream *self,
	    int af, const uint8_t *addr, _getdns_upstream **new_upstream);
	/* For tls_upstream and the descendant doh_upstream */
	SSL_CTX *(*setup_tls_ctx)(_getdns_upstream *self);
} _getdns_upstream_vmt;


/* Upstream is the base class from which all upstream types inherit.
 */
struct _getdns_upstream {
        _getdns_upstream     *parent;
        _getdns_upstream     *children;
        _getdns_upstream     *next;
	_getdns_upstream_vmt *vmt;
	upstream_caps         may;

	/* This upstream is running and will process requests from
	 * the waiting queues for its transport capabilities.
	 */
	unsigned int          processing : 1;
};

_getdns_upstream *_getdns_next_upstream(_getdns_upstream *current,
    upstream_caps cap, _getdns_upstream *stop_at);

getdns_return_t _getdns_append_upstream(_getdns_upstream *parent,
    const char *addr_str, _getdns_upstream **new_upstream);

/*---------------------------------------------------------------------------*/


typedef struct getdns_netreq_fifo {
	getdns_network_req *head;
	getdns_network_req *last;
} getdns_netreq_fifo;

typedef struct _getdns_upstreams {
	_getdns_upstream    super;
	getdns_context     *context;

	/* current upstream for each statefull/statless encrypted/unecrypted
	 * combination. An upstream_iter will start (and stop) at this
	 * upstream */
	_getdns_upstream   *current[CAP_TRANS + 1];

	/* Upstreams on a waiting queue, waiting for an upstream to finish
	 * priming and pick it up */
	getdns_netreq_fifo  waiting[CAP_TRANS + 1];

	/* Number of upstreams looking at the waiting queue for the given
	 * transport.  They could be resolving (in case of named upstreams),
	 * connecting (in case of stateful upstreams), or could already be
	 * connected, but currently busy with another request.
	 *
	 * If processing becomes 0 for a given transport, the queued netreqs
	 * should be rescheduled (as long as at stays 0 of course).
	 */
	size_t              processing[CAP_TRANS + 1];
} _getdns_upstreams;

void _getdns_upstreams_init(
    _getdns_upstreams *upstreams, getdns_context *context);

void _getdns_context_set_upstreams(
    getdns_context *context, _getdns_upstreams *upstreams);

void _getdns_upstreams_cleanup(_getdns_upstreams *upstreams);

getdns_return_t _getdns_upstreams2list(
    _getdns_upstreams *upstreams, getdns_list **list_r);

/*---------------------------------------------------------------------------*/


typedef struct upstream_iter {
	_getdns_upstream     *current;
	upstream_caps         cap;
	_getdns_upstream     *stop_at;
	size_t                skip_sz;
	uint8_t              *skip_bits;
} upstream_iter;

_getdns_upstream *upstream_iter_init(upstream_iter *iter,
    _getdns_upstreams *upstreams, upstream_caps cap);

_getdns_upstream *upstream_iter_next(upstream_iter *iter);

/* Mix13 from
 * http://zimbry.blogspot.it/2011/09/better-bit-mixing-improving-on.html */
static inline uint64_t bitmix64_hash(uint64_t x)
{   x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
;   x = (x ^ (x >> 27)) * 0x94d049bb133111eb
; return x ^ (x >> 31); }

static inline int upstream_visited(upstream_iter *i, _getdns_upstream *u)
{ size_t bit; if (!i || !i->skip_sz || !u)  return 0
; bit = (size_t)(bitmix64_hash((uint64_t)u) & (i->skip_sz - 1))
; return i->skip_bits[bit >> 3] & (1 << (bit & 7)); }

typedef enum getdns_tsig_algo_ {
        GETDNS_NO_TSIG_     = 0, /* Do not use tsig */
        GETDNS_HMAC_MD5_    = 1, /* 128 bits */
        GETDNS_GSS_TSIG_    = 2, /* Not supported */
        GETDNS_HMAC_SHA1_   = 3, /* 160 bits */
        GETDNS_HMAC_SHA224_ = 4,
        GETDNS_HMAC_SHA256_ = 5,
        GETDNS_HMAC_SHA384_ = 6,
        GETDNS_HMAC_SHA512_ = 7
} getdns_tsig_algo_;

typedef struct _tsig_st {
	uint8_t           tsig_dname[256];
	size_t            tsig_dname_len;
	size_t            tsig_size;
	uint8_t           tsig_key[256];
	getdns_tsig_algo_ tsig_alg;
} _tsig_st;

#endif /* _GETDNS_UPSTREAMS_H_ */
