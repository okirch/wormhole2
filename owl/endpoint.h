/*
 * endpoint.h
 *
 * Wrapper class for sockets, ttys etc
 *
 *   Copyright (C) 2020 Olaf Kirch <okir@suse.de>
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

#ifndef _ENDPOINT_H
#define _ENDPOINT_H

#include <sys/poll.h>
#include "queue.h"

typedef struct endpoint endpoint_t;

struct endpoint {
	/* For now, we support only endpoints with a single fd.
	 * If needed, stuff like pairs of named pipes could be added
	 * later */
	int		fd;

	unsigned int	write_shutdown_requested : 1,
			write_shutdown_sent : 1,
			read_shutdown_received : 1;
	bool		nuke_me;
	bool		have_unconsumed_data;

	bool		debug;
	char *		__debug_name;

	queue_t		sendq;
	queue_t	 *	recvq;

	/* A size hint for how much we can (try to) send in one go.
	 */
	unsigned int	send_size_hint;

	/* A mask of POLL* constants.
	 * A socket in listen mode will assert POLLIN only.
	 * A connected socket will set this to POLLIN|POLLOUT initially.
	 *   When the remote closes the socket, we should clean POLLIN
	 *   and wait until we have drained any queued up data.
	 *
	 * A pty master will set this to POLLIN|POLLOUT, and clear
	 *   the mask when receiving a hangup indication from the
	 *   slave.
	 */
	int		poll_mask;

	struct sender *	sender;
	struct receiver *receiver;

	const struct endpoint_ops *ops;

	struct endpoint_callback *eof_callbacks;
	struct endpoint_callback *close_callbacks;
	struct endpoint_callback *accept_callbacks;
	struct endpoint_callback *config_change_callbacks;
};

/* These should really be called transport_ops */
struct endpoint_ops {
	int		(*poll)(const struct endpoint *, struct pollfd *, unsigned int mask);
	size_t		(*send_size_hint)(const struct endpoint *);
	int		(*send)(struct endpoint *, const void *, size_t);
	int		(*recv)(struct endpoint *, void *, size_t);
	int		(*shutdown_write)(struct endpoint *);
};

struct event {
	unsigned int	type;
};

struct sender {
	struct sender *	next;

	void *		handle;
	void		(*get_data)(struct endpoint *, struct queue *, struct sender *);

	struct queue **	sendqp;
	struct queue	__queue;
};

struct receiver {
	struct receiver *next;

	void *		handle;
	bool		(*push_data)(struct endpoint *, struct queue *, struct receiver *);
	void		(*push_event)(struct event *, struct receiver *);

	struct queue *	recvq;
	struct queue	__queue;
};

typedef void		endpoint_callback_fn_t(struct endpoint *ep, void *app_handle);
struct endpoint_callback {
	endpoint_callback_fn_t *callback_fn;
	void *		app_handle;

	struct endpoint_callback *next;
};


extern struct endpoint *endpoint_new_socket(int fd);
extern struct endpoint *endpoint_new_pty(int fd);
extern struct endpoint *endpoint_new_listener(int fd);
extern void		endpoint_set_debug(struct endpoint *, const char *name, int num);
extern void		endpoint_set_name(struct endpoint *ep, const char *name, int num);
extern const char *	endpoint_debug_name(const struct endpoint *);
extern void		endpoint_shutdown_write(struct endpoint *);
extern void		endpoint_close(struct endpoint *);
extern void		endpoint_free(struct endpoint *);
extern unsigned int	endpoint_tailroom(const struct endpoint *ep);
extern int		endpoint_enqueue(struct endpoint *ep, const void *, size_t);
extern int		endpoint_transmit(struct endpoint *ep);
extern int		endpoint_receive(struct endpoint *ep);
extern void		endpoint_eof_from_peer(struct endpoint *ep);

extern void		endpoint_register_eof_callback(struct endpoint *ep,
				endpoint_callback_fn_t *, void *);
extern void		endpoint_register_close_callback(struct endpoint *ep,
				endpoint_callback_fn_t *, void *);
extern void		endpoint_register_accept_callback(struct endpoint *ep,
				endpoint_callback_fn_t *, void *);
extern void		endpoint_register_config_change_callback(struct endpoint *ep,
				endpoint_callback_fn_t *, void *);
extern void		__endpoint_invoke_callbacks(struct endpoint *ep, struct endpoint_callback **, bool oneshot);

extern void		endpoint_set_upper_layer(struct endpoint *ep,
				struct sender *, struct receiver *);

extern endpoint_t *	endpoint_create_unix_client(const char *socket_name);

extern void		io_register_endpoint(struct endpoint *ep);
extern int		io_mainloop(long timeout);
extern void		io_mainloop_exit(void);
extern void		io_mainloop_detect_stalls(void);
extern void		io_mainloop_config_changed(void);
extern void		io_close_all(void);
extern unsigned long	io_timestamp_ms(void);
extern unsigned int	io_register_event_type(const char *);

#define endpoint_debug(ep, msg ...) \
	do {								\
		const endpoint_t *__ep = (ep);				\
		if (__ep && __ep->debug)				\
			log_debug_id(endpoint_debug_name(__ep), ##msg);	\
	} while (0)

#define endpoint_error(ep, msg ...) \
	do {								\
		const endpoint_t *__ep = (ep);				\
		if (__ep && __ep->debug)				\
			log_error_id(endpoint_debug_name(__ep), ##msg);	\
		else							\
			log_error(msg);					\
	} while (0)

static inline size_t
endpoint_send_size_hint(const struct endpoint *ep)
{
	if (ep->ops->send_size_hint == NULL)
		return 0;

	return ep->ops->send_size_hint(ep);
}

static inline int
endpoint_poll(const struct endpoint *ep, struct pollfd *pfd, unsigned int mask)
{
	return ep->ops->poll(ep, pfd, mask);
}

static inline int
endpoint_send(struct endpoint *ep, const void *p, size_t len)
{
	return ep->ops->send(ep, p, len);
}

static inline int
endpoint_recv(struct endpoint *ep, void *p, size_t len)
{
	return ep->ops->recv(ep, p, len);
}

static inline void
endpoint_data_source_callback(struct endpoint *ep)
{
	struct sender *sender = ep->sender;

	if (sender && sender->get_data)
		sender->get_data(ep, &ep->sendq, sender);
}

static inline void
endpoint_data_sink_callback(struct endpoint *ep)
{
	struct receiver *receiver = ep->receiver;

	if (receiver && receiver->push_data && ep->recvq) {
		if (receiver->push_data(ep, ep->recvq, receiver)) {
			endpoint_debug(ep, "receiver could not process all data");
			ep->have_unconsumed_data = true;
		}
	}
}

static inline bool
endpoint_eof_callback(struct endpoint *ep)
{
	if (!ep->eof_callbacks)
		return false;

	__endpoint_invoke_callbacks(ep, &ep->eof_callbacks, true);
	return true;
}

static inline void
endpoint_close_callback(struct endpoint *ep)
{
	__endpoint_invoke_callbacks(ep, &ep->close_callbacks, true);
}

static inline void
endpoint_config_change_callback(struct endpoint *ep)
{
	__endpoint_invoke_callbacks(ep, &ep->config_change_callbacks, false);
}

extern void	endpoint_accept_callback(struct endpoint *listener, struct endpoint *new_sock);

#endif /* _ENDPOINT_H */
