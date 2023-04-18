/*
 * pty.c
 *
 * Wrapper class for pty endpoints
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

static size_t
__endpoint_pty_send_size_hint(const struct endpoint *ep)
{
	unsigned int size_hint = 0;

	if (ep->send_size_hint) {
		int bytes;

		if (ioctl(ep->fd, TIOCOUTQ, &bytes) >= 0
		 && (unsigned int) bytes <= ep->send_size_hint) {
			size_hint = ep->send_size_hint - bytes;
		}

	}

	if (size_hint == 0)
		size_hint = 128; /* arbitrary */

	return size_hint;
}

static int
__endpoint_pty_send(struct endpoint *ep, const void *p, size_t len)
{
	int n;

	n = write(ep->fd, p, len);
	if (n < 0)
		log_error("pty send: %m\n");

	endpoint_debug(ep, "pty_send(%u bytes) = %d", len, n);
	return n;
}

static int
__endpoint_pty_recv(struct endpoint *ep, void *p, size_t len)
{
	int n;

	n = read(ep->fd, p, len);
	if (n < 0)
		log_error("pty recv: %m\n");

	endpoint_debug(ep, "pty_recv(%u bytes) = %d", len, n);
	return n;
}

static int
__endpoint_pty_shutdown_write(struct endpoint *ep)
{
	/* Not implemented yet */
	return 0;
}

static struct endpoint_ops __endpoint_pty_ops = {
	.poll		= __endpoint_poll_generic,
	.send_size_hint	= __endpoint_pty_send_size_hint,
	.send		= __endpoint_pty_send,
	.recv		= __endpoint_pty_recv,
	.shutdown_write	= __endpoint_pty_shutdown_write,
};

struct endpoint *
endpoint_new_pty(int fd)
{
	struct endpoint *ep;
	int flags;

	if ((flags = fcntl(fd, F_GETFL, 0)) < 0) {
		fprintf(stderr, "fcntl(pty, F_GETFL): %m\n");
		return NULL;
	}

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		fprintf(stderr, "fcntl(pty, F_SETFL, O_NONBLOCK): %m\n");
		return NULL;
	}

	ep = endpoint_new(fd, &__endpoint_pty_ops);

	/* There's an ioctl for inquiring the buffer size */
	ep->send_size_hint = 4096;

	ep->poll_mask = POLLIN | POLLOUT;
	return ep;
}
