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

#define CAP_STATEFUL          0x0001;
#define CAP_ENCRYPTED         0x0002;
#define CAP_AUTHENTICATED     0x0004;

#define CAP_QNAME_MIN         0x0008;
#define CAP_OOOR              0x0010;
#define CAP_EDNS0             0x0020;
#define CAP_KEEPALIVE         0x0040;
#define CAP_PADDING           0x0080;

#define CAP_DNSSEC_VALIDATION 0x0100;
#define CAP_DNSSEC_SIGS       0x0200;
#define CAP_DNSSEC_NSECS      0x0400;
#define CAP_DNSSEC_WILDCARDS  0x0800;

typedef uint16_t upstream_caps;

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
{ return (req & cap) == req; }

typedef struct _getdns_upstream {
        struct _getdns_upstream *children;
        struct _getdns_upstream *parent;
        struct _getdns_upstream *next;
	upstream_caps            may;
	upstream_caps            can;
} _getdns_upstream;

struct getdns_context;
typedef struct _getdns_upstreams {
	union {
		_getdns_upstream u;
		struct {
			_getdns_upstream      *children;
			_getdns_upstream      *parent; /* NULL */
			struct getdns_context *context;
		} r;
	} super;

	/* current upstream for each statuful/encrypted/authenticated combi */
	_getdns_upstream *current[8];
} _getdns_upstreams;

void _getdns_upstreams_init(
    _getdns_upstreams *upstreams, struct getdns_context *context);

struct getdns_context *_getdns_upstream_get_context(_getdns_upstream *upstream);

_getdns_upstream *_getdns_next_upstream(_getdns_upstream *current,
    upstream_caps cap, _getdns_upstream *stop_at);

typedef struct upstream_iter {
	_getdns_upstream     *current;
	upstream_caps cap;
	_getdns_upstream     *stop_at;
} upstream_iter;

_getdns_upstream *upstream_iter_init(upstream_iter *iter,
    _getdns_upstreams *upstreams, upstream_caps cap);

_getdns_upstream *upstream_iter_next(upstream_iter *iter);

#endif /* _GETDNS_UPSTREAMS_H_ */
