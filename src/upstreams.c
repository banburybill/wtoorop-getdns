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

void
_getdns_upstreams_init(_getdns_upstreams *upstreams, getdns_context *context)
{
	assert(upstreams);
	(void) memset(upstreams, 0, sizeof(_getdns_upstreams));
	upstreams->super.r.context = context;
}

getdns_context *
_getdns_upstream_get_context(_getdns_upstream *upstream)
{
	assert(upstream);
	while (upstream->parent)
		upstream = upstream->parent;
	return ((_getdns_upstreams *)upstream)->super.r.context;
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

_getdns_upstream *upstream_iter_init(upstream_iter *iter,
    _getdns_upstreams *upstreams, upstream_caps cap)
{
	if (!iter) return NULL;
	iter->cap = cap;
	iter->stop_at = NULL;
	if (!(iter->current = upstreams->current[cap & 7])) {
		_getdns_upstream *current = upstreams->super.r.children;

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

