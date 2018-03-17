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
typedef uint16_t upstream_caps;

#define CAP_STATELESS         0x0001
#define CAP_STATEFUL          0x0002
#define CAP_UNENCRYPTED       0x0004
#define CAP_ENCRYPTED         0x0008
#define CAP_TRANS             0x000f

#define CAP_AUTHENTICATED     0x0010 /* Not initialized with CAP_MIGHT */
#define CAP_MIGHT             0xFFE0
#define CAP_RESOLVED          0x0020 /* Not with upstreams without address */

#define CAP_OOOR              0x0040
#define CAP_QNAME_MIN         0x0080

#define CAP_EDNS0             0x0100
#define CAP_KEEPALIVE         0x0200
#define CAP_PADDING           0x0400

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
#define UPSTREAM_AS_DICT(UP, DICT_R)    ((UP)->vmt->as_dict((UP), (DICT_R)))
#define UPSTREAM_GET_NAME(UP)           ((UP)->vmt->get_name((UP)))
#define UPSTREAM_GET_ADDR(UP, LEN_R)    ((UP)->vmt->get_addr((UP), (LEN_R)))
#define UPSTREAM_GET_TRANSPORT_NAME(UP) ((UP)->vmt->get_transport_name((UP)))

#define UPSTREAM_SUBMIT(UP, NETREQ, MS) ((UP)->vmt->submit((UP), (NETREQ), (MS)))
#define UPSTREAM_REVOKE(UP, NETREQ)     ((UP)->vmt->revoke((UP), (NETREQ)))
#define UPSTREAM_ERRED(UP)              ((UP)->vmt->erred((UP)))

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
	 *                             as backing off this upstream when needed.
	 */
	int             (*submit)(_getdns_upstream *s, getdns_network_req *netreq, uint64_t *now_ms);

	/* revoke() deregisters the netreq with the upstream.
	 * This may involve:
	 *   - Removing the netreq from data structures within the upstream.
	 *   - Closing sockets and freeing other resources.
	 *   - Clearing or rescheduling I/O events.
	 */
	void            (*revoke)(_getdns_upstream *s, getdns_network_req *netreq);

	/* erred() is called when the upstream failed (for a request).
	 * The number of failures are tracked, and the upstream is registered
	 * to be backed off if needed.  A backed off upstream will result in
	 * STUB_TRY_NEXT_UPSTREAM returned from submit().
	 */
	void            (*erred)(_getdns_upstream *s);
} _getdns_upstream_vmt;

struct _getdns_upstream {
        _getdns_upstream     *parent;
        _getdns_upstream     *children;
        _getdns_upstream     *next;
	_getdns_upstream_vmt *vmt;
	upstream_caps         may;
	upstream_caps         can;
};

_getdns_upstream *_getdns_next_upstream(_getdns_upstream *current,
    upstream_caps cap, _getdns_upstream *stop_at);

getdns_return_t _getdns_append_upstream(_getdns_upstream *parent,
    const char *addr_str, _getdns_upstream **new_upstream);

/*---------------------------------------------------------------------------*/


typedef struct _getdns_upstreams {
	_getdns_upstream  super;
	getdns_context   *context;
	/* current upstream for each statuful/encrypted/authenticated combi */
	_getdns_upstream *current[CAP_TRANS + 1];
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
	upstream_caps cap;
	_getdns_upstream     *stop_at;
} upstream_iter;

_getdns_upstream *upstream_iter_init(upstream_iter *iter,
    _getdns_upstreams *upstreams, upstream_caps cap);

_getdns_upstream *upstream_iter_next(upstream_iter *iter);


#endif /* _GETDNS_UPSTREAMS_H_ */
