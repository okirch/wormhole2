/*
 * mainloop.c
 *
 * I/O mainloop processing
 *
 *   Copyright (C) 2020-2023 Olaf Kirch <okir@suse.de>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <assert.h>
#include "endpoint.h"
#include "timers.h"
#include "tracing.h"

#define ENDPOINT_MAX	1024
#define EVENT_MAX	16

static struct endpoint *io_endpoints[ENDPOINT_MAX];
static unsigned int	io_endpoint_count;
static bool		__io_mainloop_exit_next = false;
static bool		__io_mainloop_detect_stalls = false;
static bool		__io_mainloop_config_changed = false;

static const char *	io_event_ids[EVENT_MAX];
static unsigned int	io_event_id_count;

static void		pollinfo_print_before(unsigned int, struct endpoint **, struct pollfd *);
static void		pollinfo_print_after(unsigned int, struct endpoint **, struct pollfd *);
static void		pollinfo_print_failed(void);

static const char *	io_strpollevents(int);
static void		io_stall_detect(unsigned long ts, const struct pollfd *pfd, unsigned int nfds);
static void		io_display_sockets(const struct pollfd *pfd, unsigned int nfds);

void
io_register_endpoint(struct endpoint *ep)
{
	assert(io_endpoint_count < ENDPOINT_MAX);
	assert(ep);
	io_endpoints[io_endpoint_count++] = ep;
}

void
io_close_all(void)
{
	while (io_endpoint_count) {
		struct endpoint *ep = io_endpoints[--io_endpoint_count];

		endpoint_free(ep);
	}
}

void
io_close_dead(void)
{
	struct endpoint *dead[ENDPOINT_MAX];
	unsigned int i, j, ndead = 0;

	for (i = j = 0; i < io_endpoint_count; ++i) {
		struct endpoint *ep = io_endpoints[i];

		if (ep->nuke_me || (ep->write_shutdown_sent && ep->read_shutdown_received)) {
			endpoint_debug(ep, "socket is a zombie");
			dead[ndead++] = ep;

			if (ep->eof_callbacks) {
				/* FIXME: invoke the EOF callbacks now? */
			}

			endpoint_close_callback(ep);
		} else {
			io_endpoints[j++] = ep;
		}
	}
	io_endpoint_count = j;

	for (i = 0; i < ndead; ++i) {
		struct endpoint *zombie = dead[i];

		for (j = 0; j < io_endpoint_count; ++j) {
			struct endpoint *ep = io_endpoints[j];

			if (zombie->recvq == &ep->sendq) {
				endpoint_debug(ep, "socket peer is a zombie");
				endpoint_shutdown_write(ep);
			}
			if (ep->recvq == &zombie->sendq) {
				/* XXX warn? */
				ep->recvq = NULL;
			}
		}

		endpoint_debug(zombie, "DESTROYED");
		endpoint_free(zombie);
	}
}

unsigned long
io_timestamp_ms(void)
{
	struct timeval tv;

	if (gettimeofday(&tv, NULL) < 0) {
		log_error("gettimeofday: %m");
		exit(66);
	}
	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

void
io_mainloop_exit(void)
{
	__io_mainloop_exit_next = true;
}

void
io_mainloop_detect_stalls(void)
{
	__io_mainloop_detect_stalls = true;
}

void
io_mainloop_config_changed(void)
{
	__io_mainloop_config_changed = true;
}

static inline long
io_mainloop_timeout(unsigned long until)
{
	owl_timeout_t timeout_state;
	unsigned long now;
	long wait_ms;

	/* First, check all active owl_timers */
	owl_timeout_init(&timeout_state);
	owl_timers_update_timeout(&timeout_state);
	wait_ms = owl_timeout_msec(&timeout_state);
	if (wait_ms < 0)
		wait_ms = 1000;

	if (until != 0) {
		now = io_timestamp_ms();
		if (now + wait_ms >= until)
			return 0;
		wait_ms = until - now;
	}

	if (wait_ms > 1000)
		wait_ms = 1000;

	return wait_ms;
}

int
io_mainloop(long timeout)
{
	unsigned long until = 0;

	if (timeout >= 0)
		until = io_timestamp_ms() + timeout;

	while (io_endpoint_count) {
		struct pollfd pfd[ENDPOINT_MAX];
		struct endpoint *watching[ENDPOINT_MAX];
		int nfds = 0, i, count;
		unsigned long now, wait_ms;

		if (__io_mainloop_exit_next) {
			__io_mainloop_exit_next = false;
			break;
		}

		for (i = 0; i < io_endpoint_count; ++i) {
			struct endpoint *ep = io_endpoints[i];

			if (__io_mainloop_config_changed)
				endpoint_config_change_callback(ep);

			if (!ep->write_shutdown_requested)
				endpoint_data_source_callback(ep);

			if (ep->have_unconsumed_data) {
				ep->have_unconsumed_data = false;
				endpoint_data_sink_callback(ep);
			}

			if (endpoint_poll(ep, &pfd[nfds], ~0) > 0)
				watching[nfds++] = ep;
		}

		__io_mainloop_config_changed = false;

		if (nfds == 0) {
			fprintf(stderr, "%s: %u sockets but they're all shy\n", __func__, io_endpoint_count);
			io_display_sockets(NULL, 0);
			break;
		}

		wait_ms = io_mainloop_timeout(until);
		now = io_timestamp_ms();

		pollinfo_print_before(nfds, watching, pfd);

		if (poll(pfd, nfds, wait_ms) < 0 && errno != EINTR) {
			pollinfo_print_failed();
			log_error("poll: %m");
			return -1;
		}

		pollinfo_print_after(nfds, watching, pfd);
		owl_timers_run();

		/* For testing purposes only */
		if (__io_mainloop_detect_stalls)
			io_stall_detect(now, pfd, nfds);

		for (i = 0; i < nfds; ++i) {
			struct endpoint *ep = watching[i];

			if (pfd[i].revents == POLLHUP) {
				endpoint_debug(ep, "hangup from client");
				endpoint_eof_from_peer(ep);
				pfd[i].revents = 0;
			}
		}

		for (i = 0; i < nfds; ++i) {
			struct endpoint *ep = watching[i];

			if (pfd[i].revents & POLLOUT) {
				endpoint_debug(ep, "socket can send (%lu bytes in queue)", queue_available(&ep->sendq));
				count = endpoint_transmit(ep);
				if (count < 0) {
					endpoint_error(ep, "socket transmit error");
					ep->nuke_me = true;
					continue;
				}

				endpoint_debug(ep, "socket transmitted %d bytes", count);
				if (ep->write_shutdown_requested && !ep->write_shutdown_sent)
					endpoint_shutdown_write(ep);
			}
		}

		for (i = 0; i < nfds; ++i) {
			struct endpoint *ep = watching[i];

			if (pfd[i].revents & POLLIN) {
				endpoint_debug(ep, "socket has data");
				count = endpoint_receive(ep);
				if (count < 0) {
					endpoint_error(ep, "socket receive error");
					ep->nuke_me = true;
					continue;
				}
				if (count == 0) {
					endpoint_debug(ep, "socket received end of file from peer");
					endpoint_eof_from_peer(ep);
					continue;
				}

				endpoint_debug(ep, "socket received %d bytes", count);
				endpoint_data_sink_callback(ep);
			}
		}

		io_close_dead();
	}

	return 0;
}

unsigned int
io_register_event_type(const char *name)
{
	unsigned int id;

	assert(io_event_id_count < EVENT_MAX);

	id = io_event_id_count++;
	io_event_ids[id] = name;
	return id;
}

const char *
io_identify_event(unsigned int id)
{
	if (id >= io_event_id_count)
		return "UNKNOWN";

	return io_event_ids[id];
}

static const char *
io_strpollevents(int ev)
{
	if (ev == POLLHUP)
		return "POLLHUP";
	if (ev == POLLERR)
		return "POLLERR";
	if (ev == POLLNVAL)
		return "POLLNVAL";

	switch (ev & (POLLIN|POLLOUT)) {
	case 0:
		return "";
	case POLLIN:
		return "IN";
	case POLLOUT:
		return "OUT";
	case POLLIN|POLLOUT:
		return "IN|OUT";
	}

	return "?";
}

static const char *
io_strqueueinfo(const struct queue *q)
{
	static char buffer[62];

	if (q == NULL)
		return "<NIL>";

	snprintf(buffer, sizeof(buffer), "avail %lu; tailroom %lu",
			queue_available(q),
			queue_tailroom(q));
	return buffer;
}

static void
io_stall_detect(unsigned long ts, const struct pollfd *pfd, unsigned int nfds)
{
	unsigned long delay;

	delay = io_timestamp_ms() - ts;
	if (delay < 500)
		return;

	fprintf(stderr, "====\n");
	fprintf(stderr, "IO stall for %lu ms\n", delay);
	io_display_sockets(pfd, nfds);
	fprintf(stderr, "====\n");
}

void
io_display_sockets(const struct pollfd *pfd, unsigned int nfds)
{
	unsigned int i, poll_i;

	for (i = poll_i = 0; i < io_endpoint_count; ++i) {
		struct endpoint *ep = io_endpoints[i];
		unsigned int events = 0;

		if (poll_i < nfds && pfd[poll_i].fd == ep->fd)
			events = pfd[poll_i++].events;

		fprintf(stderr, "%-20s poll%s%s%s%s %s\n",
				endpoint_debug_name(ep),
				ep->write_shutdown_requested? " write_shutdown_requested" : "",
				ep->write_shutdown_sent? " write_shutdown_sent" : "",
				ep->read_shutdown_received? " read_shutdown_received" : "",
				ep->have_unconsumed_data? " have_unconsumed_data" : "",
				io_strpollevents(events));
		fprintf(stderr, "    sendq %s\n", io_strqueueinfo(&ep->sendq));
		fprintf(stderr, "    recvq %s\n", io_strqueueinfo(ep->recvq));
	}
}

static const char *
__pollinfo_print(unsigned int nfds, struct endpoint **watching, struct pollfd *pfd, bool before)
{
	static char buffer[256];
	unsigned int i, pos, last_pos, left;

	last_pos = pos = 0;
	memset(buffer, 0, sizeof(buffer));

	for (i = 0; i < nfds; ++i) {
		struct endpoint *ep = watching[i];
		int events;
		char info[64];

		if (before)
			events = pfd[i].events;
		else
			events = pfd[i].revents;

		if (!ep->debug || !events)
			continue;

		snprintf(info, sizeof(info), "%s%s(%s)",
				pos? ", " : "",
				endpoint_debug_name(ep), io_strpollevents(events));

		left = sizeof(buffer) - pos;
		if (strlen(info) + 1 < left) {
			strcpy(buffer + pos, info);
			pos += strlen(info);
		} else if (left >= 5) {
			strcpy(buffer + pos, " ...");
			break;
		} else {
			strcpy(buffer + last_pos, " ...");
			break;
		}
	}

	if (pos == 0)
		return NULL;

	buffer[pos] = '\0';
	return buffer;
}

static bool	__pollinfo_printed;

void
pollinfo_print_before(unsigned int nfds, struct endpoint **watching, struct pollfd *pfd)
{
	const char *msg;

	__pollinfo_printed = false;
	if ((msg = __pollinfo_print(nfds, watching, pfd, true)) == NULL)
		return;

	trace("%-20s poll(%s) = ", "", msg);
	__pollinfo_printed = true;
}

void
pollinfo_print_after(unsigned int nfds, struct endpoint **watching, struct pollfd *pfd)
{
	const char *msg;

	if (__pollinfo_printed) {
		msg = __pollinfo_print(nfds, watching, pfd, false);
		trace("%s\n", msg? : "timeout");
	}
}

void
pollinfo_print_failed(void)
{
	if (__pollinfo_printed)
		trace("error");
}
