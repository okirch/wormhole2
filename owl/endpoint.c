/*
 * endpoint.c
 *
 * Wrapper class for sockets, ttys etc
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
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <assert.h>

#include "endpoint.h"
#include "tracing.h"

static void	__endpoint_sender_free(struct sender *s);
static void	__endpoint_receiver_free(struct receiver *r);
static void	__io_free_callbacks(struct endpoint_callback **list);

struct endpoint *
endpoint_new(int fd, const struct endpoint_ops *ops)
{
	struct endpoint *ep;

	ep = calloc(1, sizeof(*ep));
	ep->fd = fd;
	ep->ops = ops;

	return ep;
}

void
endpoint_set_name(struct endpoint *ep, const char *name, int num)
{
	if (ep->__debug_name)
		free(ep->__debug_name);
	if (num < 0) {
		ep->__debug_name = strdup(name);
	} else {
		char namebuf[66];

		snprintf(namebuf, sizeof(namebuf), "%s%d", name, num);
		ep->__debug_name = strdup(namebuf);
	}
}

void
endpoint_set_debug(struct endpoint *ep, const char *name, int num)
{
	if (name)
		endpoint_set_name(ep, name, num);
	ep->debug = true;
}

const char *
endpoint_debug_name(const struct endpoint *ep)
{
	static char namebuf[64];

	if (ep->__debug_name)
		return ep->__debug_name;

	snprintf(namebuf, sizeof(namebuf), "fd%d", ep->fd);
	return namebuf;
}

void
endpoint_free(struct endpoint *ep)
{
	if (ep->fd >= 0)
		close(ep->fd);

	__io_free_callbacks(&ep->eof_callbacks);
	__io_free_callbacks(&ep->close_callbacks);
	__io_free_callbacks(&ep->accept_callbacks);
	__io_free_callbacks(&ep->config_change_callbacks);

	if (ep->sender)
		__endpoint_sender_free(ep->sender);
	if (ep->receiver)
		__endpoint_receiver_free(ep->receiver);

	if (ep->__debug_name)
		free(ep->__debug_name);

	queue_destroy(&ep->sendq);
	free(ep);
}

void
endpoint_shutdown_write(struct endpoint *ep)
{
	if (!ep->write_shutdown_requested)
		endpoint_debug(ep, "write-shutdown requested");

	ep->write_shutdown_requested = 1;

	if (queue_available(&ep->sendq) == 0) {
		ep->ops->shutdown_write(ep);
		ep->write_shutdown_sent = 1;
	}
}

/*
 * Common ops functions
 */
static int
__endpoint_poll_generic(const struct endpoint *ep, struct pollfd *pfd, unsigned int poll_mask)
{
	poll_mask &= ep->poll_mask;

	/* If we have nothing queued up for sending, we shouldn't wait for POLLOUT */
	if (queue_available(&ep->sendq) == 0)
		poll_mask &= ~POLLOUT;

	/* If the receive queue has been changed to NULL, this means we have nothing
	 * to write to anymore (and we need to discard all incoming data). In order
	 * not to miss the client closing the connection, we DO assert POLLIN in this
	 * situation.
	 *
	 * If recvq is non-NULL, but we have no room to queue more incoming data,
	 * we shouldn't wait for POLLIN */
	if (ep->recvq == NULL) {
		/* NOP */
	} else
	if (queue_tailroom(ep->recvq) == 0)
		poll_mask &= ~POLLIN;

	if (poll_mask == 0)
		return 0;

	pfd->fd = ep->fd;
	pfd->events = poll_mask;
	return 1;
}

/*
 * Socket code
 */
static size_t
__endpoint_socket_send_size_hint(const struct endpoint *ep)
{
	unsigned int size_hint = 0;

	if (ep->send_size_hint) {
		int bytes;

		if (ioctl(ep->fd, SIOCOUTQ, &bytes) >= 0
		 && (unsigned int) bytes <= ep->send_size_hint) {
			size_hint = ep->send_size_hint - bytes;
		}

	}

	if (size_hint == 0)
		size_hint = 1400; /* arbitrary */

	return size_hint;
}

static int
__endpoint_socket_send(struct endpoint *ep, const void *p, size_t len)
{
	int n;

	n = send(ep->fd, p, len, MSG_DONTWAIT | MSG_NOSIGNAL);
	if (n < 0) {
		if (errno != EPIPE)
			log_error("socket send: %m\n");
	}

	return n;
}

static int
__endpoint_socket_recv(struct endpoint *ep, void *p, size_t len)
{
	int n;

	n = recv(ep->fd, p, len, MSG_DONTWAIT | MSG_NOSIGNAL);
	if (n < 0)
		log_error("socket recv: %m\n");

	return n;
}

static int
__endpoint_socket_shutdown_write(struct endpoint *ep)
{
	if (shutdown(ep->fd, SHUT_WR) < 0) {
		log_error("shutdown: %m\n");
		return -1;
	}

	return 0;
}

static struct endpoint_ops __endpoint_socket_ops = {
	.poll		= __endpoint_poll_generic,
	.send_size_hint	= __endpoint_socket_send_size_hint,
	.send		= __endpoint_socket_send,
	.recv		= __endpoint_socket_recv,
	.shutdown_write	= __endpoint_socket_shutdown_write,
};

struct endpoint *
endpoint_new_socket(int fd)
{
	struct endpoint *ep;
	socklen_t optlen;
	int size;

	ep = endpoint_new(fd, &__endpoint_socket_ops);

	optlen = sizeof(size);
	if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, &optlen) < 0) {
		log_error("getsockopt(SO_SNDBUF): %m\n");
	} else {
		assert(optlen == sizeof(size));
		ep->send_size_hint = size;
	}

	ep->poll_mask = POLLIN | POLLOUT;
	return ep;
}

/*
 * TCP listening socket
 */
static int
__endpoint_listener_poll(const struct endpoint *ep, struct pollfd *pfd, unsigned int poll_mask)
{
	/* We don't do anything fancy like limiting the number of active connections. */
	pfd->fd = ep->fd;
	pfd->events = poll_mask & ep->poll_mask;
	return 1;
}

static int
__endpoint_listener_recv(struct endpoint *ep, void *p, size_t len)
{
	struct endpoint *connected;
	int fd;

	fd = accept(ep->fd, NULL, NULL);
	if (fd < 0) {
		log_error("accept: %m\n");
		return 1;
	}

	connected = endpoint_new_socket(fd);

	if (ep->debug) {
		static unsigned int num_connected = 0;

		endpoint_set_name(connected, "conn", num_connected++);
		connected->debug = true;
	}
	endpoint_accept_callback(ep, connected);
	return 1;
}

void
endpoint_accept_callback(struct endpoint *listener, struct endpoint *new_sock)
{
	struct endpoint_callback *cb;

	for (cb = listener->accept_callbacks; cb; cb = cb->next)
		cb->callback_fn(new_sock, cb->app_handle);
}

static struct endpoint_ops __endpoint_listener_ops = {
	.poll		= __endpoint_listener_poll,
	.recv		= __endpoint_listener_recv,
};

struct endpoint *
endpoint_new_listener(int fd)
{
	struct endpoint *ep;

	ep = endpoint_new(fd, &__endpoint_listener_ops);
	ep->poll_mask = POLLIN;
	return ep;
}

int
endpoint_transmit(struct endpoint *ep)
{
	size_t send_sz, size_hint;
	void *buf;
	const void *p;
	int sent;

	send_sz = queue_available(&ep->sendq);
	if (send_sz == 0)
		return 0;

	size_hint = endpoint_send_size_hint(ep);
	if (size_hint && size_hint < send_sz)
		send_sz = size_hint;

	assert(send_sz <= QUEUE_SZ);

	buf = alloca(send_sz);

	/* Get a pointer to send_sz bytes from the send queue.
	 * If needed, this will linearize data from the send q
	 * and store it in buf. Otherwise, it may return a pointer
	 * to an internal buffer that we can send from directly.
	 */
	p = queue_peek(&ep->sendq, buf, send_sz);

	sent = endpoint_send(ep, p, send_sz);
	if (sent >= 0)
		queue_advance_head(&ep->sendq, sent);

	return sent;
}

unsigned int
endpoint_tailroom(const struct endpoint *ep)
{
	if (ep->write_shutdown_requested)
		return 0;

	return queue_tailroom(&ep->sendq);
}

int
endpoint_enqueue(struct endpoint *ep, const void *buffer, size_t count)
{
	unsigned int tailroom = endpoint_tailroom(ep);

	if (tailroom < count) {
		fprintf(stderr, "%s: not enough room in send buffer\n", __func__);
		return -1;
	}

	queue_append(&ep->sendq, buffer, count);
	return count;
}

int
endpoint_receive(struct endpoint *ep)
{
	size_t recv_sz;
	void *buf;
	int n;

	if (ep->recvq == NULL) {
		/* Discard incoming data */
		buf = alloca(4096);
		return endpoint_recv(ep, buf, 4096);
	}

	recv_sz = queue_tailroom(ep->recvq);
	if (recv_sz == 0) {
		/* XXX complain */
		fprintf(stderr, "bug: %s called without space in recvq\n", __func__);
		return 0;
	}

	buf = alloca(recv_sz);

	n = endpoint_recv(ep, buf, recv_sz);
	if (n >= 0)
		queue_append(ep->recvq, buf, n);

	return n;
}

void
endpoint_eof_from_peer(struct endpoint *ep)
{
	ep->read_shutdown_received = 1;
	ep->poll_mask &= ~POLLIN;

	if (!endpoint_eof_callback(ep)) {
		/* No callback registered for EOF handling. Just declare
		 * this endpoint dead. */
		endpoint_shutdown_write(ep);
	}

	ep->recvq = NULL;
}

void
endpoint_set_upper_layer(struct endpoint *ep, struct sender *s, struct receiver *r)
{
	ep->sender = s;
        ep->receiver = r;
	ep->recvq = r->recvq;
}

static void
__endpoint_sender_free(struct sender *s)
{
	if (s->next)
		__endpoint_sender_free(s->next);
	queue_destroy(&s->__queue);
	memset(s, 0xAA, sizeof(*s));
	free(s);
}

static void
__endpoint_receiver_free(struct receiver *r)
{
	if (r->next)
		__endpoint_receiver_free(r->next);
	queue_destroy(&r->__queue);
	memset(r, 0xAA, sizeof(*r));
	free(r);
}

/*
 * Callbacks
 */
static void
__endpoint_register_callback(struct endpoint_callback **list, endpoint_callback_fn_t *fn, void *handle)
{
	struct endpoint_callback *cb;

	cb = calloc(1, sizeof(*cb));
	cb->callback_fn = fn;
	cb->app_handle = handle;

	cb->next = *list;
	*list = cb;
}

void
endpoint_register_eof_callback(struct endpoint *ep, endpoint_callback_fn_t *fn, void *handle)
{
	__endpoint_register_callback(&ep->eof_callbacks, fn, handle);
}

void
endpoint_register_close_callback(struct endpoint *ep, endpoint_callback_fn_t *fn, void *handle)
{
	__endpoint_register_callback(&ep->close_callbacks, fn, handle);
}

void
endpoint_register_accept_callback(struct endpoint *ep, endpoint_callback_fn_t *fn, void *handle)
{
	__endpoint_register_callback(&ep->accept_callbacks, fn, handle);
}

void
endpoint_register_config_change_callback(struct endpoint *ep, endpoint_callback_fn_t *fn, void *handle)
{
	__endpoint_register_callback(&ep->config_change_callbacks, fn, handle);
}

void
__endpoint_invoke_callbacks(struct endpoint *ep, struct endpoint_callback **list, bool oneshot)
{
	struct endpoint_callback *cb;

	while ((cb = *list) != NULL) {
		cb->callback_fn(ep, cb->app_handle);

		if (oneshot) {
			*list = cb->next;
			free(cb);
		} else {
			list = &cb->next;
		}
	}
}

void
__io_free_callbacks(struct endpoint_callback **list)
{
	struct endpoint_callback *cb;

	while ((cb = *list) != NULL) {
		*list = cb->next;
		free(cb);
	}
}

