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

typedef struct upstream_capabilities {
	unsigned int stateful         : 1;
	unsigned int encrypted        : 1;
	unsigned int authenticated    : 1;

	unsigned int qname_min        : 1;
	unsigned int ooor             : 1;
	unsigned int edns0            : 1;
	unsigned int keepalive        : 1;
	unsigned int padding          : 1;
	unsigned int dnssec_validation: 1;
	unsigned int dnssec           : 2; /* 1 = positive (i.e. sigs)
					    * 2 = negative (i.e. nsecs)
					    * 3 = wildcard (i.e. bind bug )*/
} upstream_capabilities;

typedef struct _getdns_upstream _getdns_upstream;

typedef struct _getdns_upstreams {
	_getdns_upstream *children;

	/* current upstream for each statuful/encrypted/authenticated combi */
	_getdns_upstream *current[8];
} _getdns_upstreams;

_getdns_upstream *_getdns_next_upstream(_getdns_upstream *current,
    upstream_capabilities cap, _getdns_upstream *stop_at);

typedef struct upstream_iter {
	_getdns_upstream     *current;
	upstream_capabilities cap;
	_getdns_upstream     *stop_at;
} upstream_iter;

_getdns_upstream *upstream_iter_init(upstream_iter *iter,
    _getdns_upstreams *upstreams, upstream_capabilities cap);

struct _getdns_upstream {
	_getdns_upstreams *parent;
	_getdns_upstream  *next;
};

#endif /* _GETDNS_UPSTREAMS_H_ */
