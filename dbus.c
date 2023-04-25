/*
 * DBus relay manager
 *
 *   Copyright (C) 2023 Olaf Kirch <okir@suse.de>
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
 *
 * This takes care of spawning the appropriate forwarding processes.
 */

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/poll.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>

#include "owl/bufparser.h"
#include "dbus-relay.h"
#include "tracing.h"
#include "util.h"

#define DBUS_SYSTEM_BUS_SOCKET	"/run/dbus/system_bus_socket"

typedef struct dbus_client	dbus_client_t;
typedef struct dbus_bridge_port	dbus_bridge_port_t;
typedef struct dbus_service_proxy dbus_service_proxy_t;
typedef struct dbus_sigrec	dbus_sigrec_t;
typedef struct dbus_timer	dbus_timer_t;

typedef const struct dbus_client_ops dbus_client_ops_t;

extern bool			dbus_bridge_port_acquire_name(dbus_bridge_port_t *port, const char *name);
extern void			dbus_bridge_port_event_name_lost(dbus_bridge_port_t *port, const char *name);
extern void			dbus_bridge_port_event_name_acquired(dbus_bridge_port_t *port, const char *name);
static bool			dbus_service_proxy_connect(dbus_service_proxy_t *proxy, dbus_bridge_port_t *port);

static void			dbus_service_proxy_stop(dbus_service_proxy_t *proxy);

struct dbus_client {
	char *			debug_name;
	sd_bus *		h;

	struct {
		dbus_client_ops_t *ops;
		void *		data;
	} impl;

	char *			bus_name;	/* local bus name, :x.y */
	char *			request_name;	/* well-known name to request */

	dbus_sigrec_t *		signal_handlers;
};

struct dbus_client_ops {
	void			(*connection_lost)(dbus_client_t *);
	void			(*process_registered_names)(dbus_client_t *, const char **names, unsigned int count);
	void			(*name_acquired)(dbus_client_t *, const char *);
	void			(*name_lost)(dbus_client_t *, const char *);
	void			(*name_owner_changed)(dbus_client_t *, const char *, const char *, const char *);
};

typedef int			dbus_timer_callback_fn_t(void *);
struct dbus_timer {
	unsigned long		initial_timeout_ms;
	unsigned long		current_timeout_ms;
	sd_event_source *	event_source;
	dbus_timer_callback_fn_t *callback;
	void *			userdata;
};


typedef void (*dbus_signal_handler_t)(dbus_client_t *dbus, sd_bus_message *msg);

struct dbus_sigrec {
	dbus_sigrec_t *		next;
	char *			interface;
	char *			member;

	dbus_signal_handler_t	handler;
};

struct dbus_service_proxy {
	dbus_service_proxy_t *	next;
	char *			bus_address;

	char *			name;
	pid_t			pid;
};

struct dbus_bridge_port {
	char *			name;
	char *			bus_address;

	bool			open_for_business;

	dbus_timer_t *		reconnect_timer;
	dbus_client_t *		dbus;
	dbus_client_t *		monitor;

	dbus_bridge_port_t *	other;

	/* On the upstream port, this is a list of names that
	 * we want to create proxies for */
	struct strutil_array	names_to_publish;

	/* On the downstream port, this is the list of proxies
	 * we actually have active. */
	dbus_service_proxy_t *	service_proxies;
};

static void		dbus_sigrec_free(dbus_sigrec_t *sig);

static void
dbus_debug(dbus_client_t *dbus, const char *fmt, ...)
{
	char msgbuf[512];
	va_list ap;

	if (tracing_level == 0)
		return;

	va_start(ap, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
	va_end(ap);

	log_debug("%s: %s", dbus->debug_name, msgbuf);
}

dbus_client_t *
dbus_client_new(const char *name, dbus_client_ops_t *ops, void *impl_data)
{
	dbus_client_t *dbus;

	dbus = calloc(1, sizeof(*dbus));
	strutil_set(&dbus->debug_name, name);
	dbus->impl.ops = ops;
	dbus->impl.data = impl_data;

	return dbus;
}

void
dbus_client_free(dbus_client_t *dbus)
{
	dbus_sigrec_t *rec;

	if (dbus->h) {
		sd_bus_close(dbus->h);
		sd_bus_unref(dbus->h);
		dbus->h = NULL;
	}

	while ((rec = dbus->signal_handlers) != NULL) {
		dbus->signal_handlers = rec->next;
		dbus_sigrec_free(rec);
	}
}

static dbus_sigrec_t *
dbus_sigrec_new(const char *interface_name, const char *member_name, dbus_signal_handler_t handler)
{
	dbus_sigrec_t *sig;

	sig = calloc(1, sizeof(*sig));
	strutil_set(&sig->interface, interface_name);
	strutil_set(&sig->member, member_name);
	sig->handler = handler;
	return sig;
}

static void
dbus_sigrec_free(dbus_sigrec_t *sig)
{
	strutil_drop(&sig->interface);
	strutil_drop(&sig->member);
	free(sig);
}

static int
dbus_client_handle_signal(sd_bus_message *m, void *ptr, sd_bus_error *ret_error)
{
	dbus_client_t *dbus = ptr;
	dbus_sigrec_t *sig;

	for (sig = dbus->signal_handlers; sig; sig = sig->next) {
		if (sd_bus_message_is_signal(m, sig->interface, sig->member)) {
			// dbus_debug(dbus, "Processing signal %s.%s", sig->interface, sig->member);
			sig->handler(dbus, m);
		}
	}
	return 0;
}

static void
dbus_client_install_signal_handler(dbus_client_t *dbus,
		const char *interface, const char *member,
		dbus_signal_handler_t handler)
{
	dbus_sigrec_t *rec;
	int r;

	if (handler == NULL)
		return;

	rec = dbus_sigrec_new(interface, member, handler);
	rec->next = dbus->signal_handlers;
	dbus->signal_handlers = rec;

	r = sd_bus_match_signal(dbus->h, NULL,
			NULL,			/* sender */
			NULL,			/* object path */
			interface,
			member,
			dbus_client_handle_signal,
			dbus);

	if (r > 0)
		dbus_debug(dbus, "installed signal handler for %s.%s", interface, member);
}

static void
dbus_client_handle_name_acquired_signal(dbus_client_t *dbus, sd_bus_message *m)
{
	const char *name = NULL;

	if (sd_bus_message_read(m, "s", &name) <= 0)
		return;

	dbus_debug(dbus, "NameAcquired: %s", name);
	if (dbus->impl.ops->name_acquired)
		dbus->impl.ops->name_acquired(dbus, name);
}

static void
dbus_client_handle_name_lost_signal(dbus_client_t *dbus, sd_bus_message *m)
{
	const char *name = NULL;

	if (sd_bus_message_read(m, "s", &name) <= 0)
		return;

	if (dbus->impl.ops->name_lost)
		dbus->impl.ops->name_lost(dbus, name);
}

static void
dbus_client_handle_name_owner_changed_signal(dbus_client_t *dbus, sd_bus_message *m)
{
	const char *name = NULL, *old_owner = NULL, *new_owner = NULL;

	if (sd_bus_message_read(m, "sss", &name, &old_owner, &new_owner) <= 0)
		return;

	/* Ignore all owner changes for :x.y bus names */
	if (name[0] == ':')
		return;

	dbus_debug(dbus, "NameOwnerChanged(%s, %s, %s)", name, old_owner, new_owner);
	if (dbus->impl.ops->name_owner_changed)
		dbus->impl.ops->name_owner_changed(dbus, name, old_owner, new_owner);
}

void
dbus_client_disconnect(dbus_client_t *dbus)
{
	if (dbus->h == NULL)
		return;

	dbus_debug(dbus, "disconnecting");
	sd_bus_unref(dbus->h);
	dbus->h = NULL;
}

static int
dbus_client_hangup_callback(sd_event_source *s, int fd, uint32_t revents, void *userdata)
{
	dbus_client_t *dbus = userdata;

	dbus_debug(dbus, "%s()", __func__);
	if (!(revents & POLLHUP))
		return 0;

	dbus_debug(dbus, "connection closed by peer");
	dbus_client_disconnect(dbus);
	sd_event_source_unref(s);
	close(fd);

	if (dbus->impl.ops->connection_lost)
		dbus->impl.ops->connection_lost(dbus);

	return 0;
}

bool
dbus_client_connect(dbus_client_t *dbus, const char *dbus_path)
{
	sd_event *event;
	int r;

	if (dbus->h != NULL) {
		log_error_id(dbus->debug_name, "already connected");
		return false;
	}

	if (dbus_path == NULL) {
		unsetenv("DBUS_SYSTEM_BUS_ADDRESS");
	} else {
		char addrstring[256];

		snprintf(addrstring, sizeof(addrstring), "unix:path=%s", dbus_path);
		setenv("DBUS_SYSTEM_BUS_ADDRESS", addrstring, 1);
	}

	if ((r = sd_bus_open_system_with_description(&dbus->h, dbus->debug_name)) < 0) {
		dbus_debug(dbus, "sd_bus_open failed: %s", strerror(-r));
		return false;
	}

	if (sd_event_default(&event) < 0)
		log_fatal("Unable to create sd-event loop");
	sd_bus_attach_event(dbus->h, event, SD_EVENT_PRIORITY_NORMAL);

	{
		int fd;

		if ((fd = sd_bus_get_fd(dbus->h)) < 0)
			log_fatal("unable to get fd of dbus client");

		/* We cannot install two event handlers for the same fd. Thus, dup()
		 * the fd and make sure dbus_client_hangup_callback() closes it */
		fd = dup(fd);

		sd_event_add_io(event, NULL, fd, EPOLLHUP, dbus_client_hangup_callback, dbus);
	}

	{
		const char *sender = NULL;

		if (sd_bus_get_unique_name(dbus->h, &sender) == 0)
			strutil_set(&dbus->bus_name, sender);
	}

	dbus_debug(dbus, "connected to DBus broker; my bus name %s", dbus->bus_name);

	if (dbus->impl.ops->name_acquired)
		dbus_client_install_signal_handler(dbus, 
			"org.freedesktop.DBus", "NameAcquired",
			dbus_client_handle_name_acquired_signal);

	if (dbus->impl.ops->name_lost)
		dbus_client_install_signal_handler(dbus, 
			"org.freedesktop.DBus", "NameLost",
			dbus_client_handle_name_lost_signal);

	if (dbus->impl.ops->name_owner_changed)
		dbus_client_install_signal_handler(dbus, 
			"org.freedesktop.DBus", "NameOwnerChanged",
			dbus_client_handle_name_owner_changed_signal);

	return true;
}

/*
 * Timers
 */
static int
__dbus_timer_callback(sd_event_source *s, uint64_t usec, void *userdata)
{
	static const unsigned long max_backoff = 30000000; /* 30 seconds */
	dbus_timer_t *timer = userdata;

	if (!timer->callback(timer->userdata)) {
		sd_event_source_set_enabled(timer->event_source, SD_EVENT_OFF);
		return 0;
	}

	if (timer->current_timeout_ms == 0) {
		timer->current_timeout_ms = timer->initial_timeout_ms;
	} else {
		timer->current_timeout_ms <<= 1;
		if (timer->current_timeout_ms > max_backoff)
			timer->current_timeout_ms = max_backoff;
	}

	/* Come back after the specified timeout */
	sd_event_source_set_time_relative(timer->event_source, timer->current_timeout_ms);
	return 1;
}


static dbus_timer_t *
dbus_timer_new(unsigned long timeout_ms, dbus_timer_callback_fn_t *callback, void *userdata)
{
	dbus_timer_t *timer;
	sd_event *event;

	timer = calloc(1, sizeof(*timer));
	timer->initial_timeout_ms = timeout_ms;
	timer->callback = callback;
	timer->userdata = userdata;

	if (sd_event_default(&event) < 0)
		log_fatal("sd_event_default failed");

	sd_event_add_time_relative(event, &timer->event_source, CLOCK_MONOTONIC, 0, timeout_ms / 10, __dbus_timer_callback, timer);
	sd_event_source_set_enabled(timer->event_source, SD_EVENT_ON);
	return timer;
}

static void
dbus_timer_restart(dbus_timer_t *timer)
{
	assert(timer->event_source);

	/* re-enable the timer and ensure it fires immediately */
	sd_event_source_set_enabled(timer->event_source, SD_EVENT_ON);
	sd_event_source_set_time_relative(timer->event_source, 0);
	timer->current_timeout_ms = 0;
}

/*
 * Create a timer connected to a bridge port
 */
static void
dbus_bridge_add_timer(dbus_bridge_port_t *port, unsigned long timeout_ms, int (*callback)(dbus_bridge_port_t *))
{
	if (port->reconnect_timer == NULL)
		port->reconnect_timer = dbus_timer_new(timeout_ms, (dbus_timer_callback_fn_t *) callback, port);
	else
		dbus_timer_restart(port->reconnect_timer);
}

/*
 * Implementation of the bridge port
 */
static void
dbus_bridge_name_acquired(dbus_client_t *dbus, const char *name)
{
	dbus_debug(dbus, "acquired name", name);
}

static void
dbus_bridge_name_lost(dbus_client_t *dbus, const char *name)
{
	dbus_debug(dbus, "lost name", name);
}

static void
dbus_bridge_process_registered_names(dbus_client_t *dbus, const char **names, unsigned int count)
{
	dbus_bridge_port_t *port = dbus->impl.data;

	if (port == NULL || port->names_to_publish.count == 0)
		return;

	while (count--) {
		const char *name = *names++;

		if (name[0] == ':')
			continue;

		dbus_debug(dbus, "  %s", name);
		dbus_bridge_port_event_name_acquired(port, name);
	}
}

static dbus_client_ops_t	dbus_impl_bridge = {
	.process_registered_names = dbus_bridge_process_registered_names,
	.name_acquired = dbus_bridge_name_acquired,
	.name_lost = dbus_bridge_name_lost,
};

/*
 * Implementation of the monitor
 */
static int
__dbus_monitor_reconnect(dbus_bridge_port_t *port)
{
	dbus_client_t *dbus = port->monitor;
	dbus_service_proxy_t *proxy;

	dbus_debug(dbus, "Trying to reconnect");
	if (dbus->h == NULL && !dbus_client_connect(dbus, port->bus_address)) {
		return 1;
	}

	dbus_debug(dbus, "Connected, opening up for business");
	port->open_for_business = true;

	/* Loop over all proxies and reconnect those as well. */
	for (proxy = port->service_proxies; proxy; proxy = proxy->next) {
		if (proxy->pid < 0)
			dbus_service_proxy_connect(proxy, port);
	}

	return 0;
}

static void
dbus_monitor_attempt_reconnect(dbus_bridge_port_t *port)
{
	dbus_client_t *dbus = port->monitor;

	if (dbus->h) {
		dbus_debug(dbus, "%s: already connected", __func__);
		return;
	}

	dbus_bridge_add_timer(port, 1000000, __dbus_monitor_reconnect);
}


static void
dbus_monitor_connection_lost(dbus_client_t *dbus)
{
	dbus_bridge_port_t *port = dbus->impl.data;
	dbus_service_proxy_t *proxy;

	/* can this happen? */
	if (dbus != port->monitor)
		return;

	dbus_debug(dbus, "lost connection to DBus broker");
	port->open_for_business = false;

	for (proxy = port->service_proxies; proxy; proxy = proxy->next)
		dbus_service_proxy_stop(proxy);

	dbus_monitor_attempt_reconnect(port);
}

static void
dbus_monitor_name_owner_changed(dbus_client_t *dbus, const char *name, const char *old_owner, const char *new_owner)
{
	dbus_bridge_port_t *port = dbus->impl.data;

	if (new_owner == NULL || *new_owner == '\0') {
		dbus_debug(dbus, "%s dropped", name);
		if (port)
			dbus_bridge_port_event_name_lost(port, name);
	} else {
		dbus_debug(dbus, "%s acquired by %s", name, new_owner);
		if (port)
			dbus_bridge_port_event_name_acquired(port, name);
	}
}

static dbus_client_ops_t	dbus_impl_monitor = {
	.connection_lost = dbus_monitor_connection_lost,
	.name_owner_changed = dbus_monitor_name_owner_changed,
	.process_registered_names = dbus_bridge_process_registered_names,
};

/*
 * DBus methods for proxy
 */
static dbus_client_ops_t	dbus_impl_proxy = {
};

/*
 * Service proxy
 */
static dbus_service_proxy_t *
dbus_service_proxy_new(const char *name, const char *bus_address)
{
	dbus_service_proxy_t *proxy;

	proxy = calloc(1, sizeof(*proxy));
	strutil_set(&proxy->name, name);
	strutil_set(&proxy->bus_address, bus_address);
	proxy->pid = -1;
	return proxy;
}

static void
__dbus_service_proxy_configure_port(dbus_forwarding_port_t *port, const char *bus_name, int fd)
{
	dbus_forwarding_port_set_bus_name(port, bus_name);
	dbus_forwarding_port_set_socket(port, fd);
}

static bool
dbus_service_proxy_start(dbus_service_proxy_t *proxy, dbus_client_t *dbus_upstream, dbus_client_t *dbus_downstream)
{
	dbus_forwarder_t *fwd;
	int upstream_fd, downstream_fd;
	pid_t pid;

	if (proxy->pid > 0) {
		log_error_id(proxy->name, "we already have an active proxy process");
		return false;
	}

	/* libsystemd is a bit overly restrictive here. Calling sd_bus_get_fd() after fork
	 * will return -ECHILD :-/
	 */
	upstream_fd = dup(sd_bus_get_fd(dbus_upstream->h));
	downstream_fd = dup(sd_bus_get_fd(dbus_downstream->h));

	pid = fork();
	if (pid < 0) {
		log_error_id(proxy->name, "unable to fork proxy process: %m");
		return false;
	}

	if (pid > 0) {
		proxy->pid = pid;
		return true;
	}

	/* we're the child process */
	fwd = dbus_forwarder_new(proxy->name);

	dbus_debug(dbus_upstream, "Configuring upstream port");
	__dbus_service_proxy_configure_port(dbus_forwarder_get_upstream(fwd), dbus_upstream->bus_name, upstream_fd);
	dbus_debug(dbus_downstream, "Configuring downstream port");
	__dbus_service_proxy_configure_port(dbus_forwarder_get_downstream(fwd), dbus_downstream->bus_name, downstream_fd);

	dbus_forwarder_eventloop(fwd);

	exit(0);
}

static void
dbus_service_proxy_stop(dbus_service_proxy_t *proxy)
{
	if (proxy->pid <= 0)
		return;

	kill(proxy->pid, SIGKILL);
	if (!procutil_wait_for(proxy->pid, NULL))
		log_error_id(proxy->name, "unable to reap proxy process");

	proxy->pid = -1;
}

static dbus_client_t *
dbus_service_proxy_create_client(dbus_service_proxy_t *proxy, dbus_bridge_port_t *port)
{
	dbus_client_t *dbus;
	char name[128];

	if (!port || !port->open_for_business)
		return NULL;

	/* Create the dbus client and connect, claiming the name we've been given */
	snprintf(name, sizeof(name), "%s:%s", port->name, proxy->name);
	dbus = dbus_client_new(name, &dbus_impl_proxy, port);
	strutil_set(&dbus->request_name, proxy->name);

	return dbus;
}

static dbus_client_t *
dbus_service_proxy_connect_downstream(dbus_service_proxy_t *proxy, dbus_bridge_port_t *port)
{
	dbus_client_t *dbus;
	int r;

	if (!(dbus = dbus_service_proxy_create_client(proxy, port)))
		return NULL;

	if (!dbus_client_connect(dbus, port->bus_address)) {
		log_error_id(dbus->debug_name, "Failed to connect to DBus");
		goto failed;
	}

	r = sd_bus_request_name(dbus->h, dbus->request_name, 0);
	if (r < 0) {
		log_error("Failed to acquire bus name %s on %s port: %s",
				dbus->request_name, port->name, strerror(-r));
		goto failed;
	}

	dbus_debug(dbus, "Acquired name %s", dbus->request_name);
	return dbus;

failed:
	dbus_client_free(dbus);
	return NULL;
}

static dbus_client_t *
dbus_service_proxy_connect_upstream(dbus_service_proxy_t *proxy, dbus_bridge_port_t *port)
{
	dbus_client_t *dbus;

	if (!(dbus = dbus_service_proxy_create_client(proxy, port)))
		return NULL;

	if (!dbus_client_connect(dbus, port->bus_address)) {
		log_error_id(dbus->debug_name, "Failed to connect to DBus");
		goto failed;
	}

	return dbus;

failed:
	dbus_client_free(dbus);
	return NULL;
}

static bool
dbus_service_proxy_connect(dbus_service_proxy_t *proxy, dbus_bridge_port_t *port)
{
	dbus_client_t *dbus_upstream, *dbus_downstream;
	bool ok = false;

	if (port->bus_address == NULL) {
		log_error("%s: cannot create proxy %s: no bus address set", port->name, proxy->name);
		return false;
	}

	if (!port->open_for_business) {
		log_debug_id(proxy->name, "Defer connect() call until the downstream bus broker is running");
		return true;
	}

	/* If a child process exists already, terminate it */
	(void) dbus_service_proxy_stop(proxy);

	log_debug("Trying to create a proxy for %s on port %s", proxy->name, port->name);
	dbus_upstream = dbus_service_proxy_connect_upstream(proxy, port->other);
	dbus_downstream = dbus_service_proxy_connect_downstream(proxy, port);
	if (dbus_upstream && dbus_downstream)
		ok = dbus_service_proxy_start(proxy, dbus_upstream, dbus_downstream);

	if (dbus_upstream)
		dbus_client_free(dbus_upstream);
	if (dbus_downstream)
		dbus_client_free(dbus_downstream);

	if (!ok) {
		log_error_id(proxy->name, "unable to create forwarding process");
		/* mark this proxy as failed */
	}

	return ok;
}

/*
 * Bridge port class
 */
dbus_bridge_port_t *
dbus_bridge_port_new(const char *name, const char *bus_address)
{
	dbus_bridge_port_t *port;

	port = calloc(1, sizeof(*port));
	strutil_set(&port->name, name);
	strutil_set(&port->bus_address, bus_address);
	return port;
}

void
dbus_bridge_port_publish(dbus_bridge_port_t *port, const char *name)
{
	strutil_array_append(&port->names_to_publish, name);
}

bool
dbus_bridge_port_monitor(dbus_bridge_port_t *port, bool deferred)
{
	char name[64];

	snprintf(name, sizeof(name), "%s-mon", port->name);
	log_debug("Creating port monitor for port %s", port->name);

	port->monitor = dbus_client_new(name, &dbus_impl_monitor, port);
	if (deferred) {
		dbus_monitor_attempt_reconnect(port);
	} else {
		if (!dbus_client_connect(port->monitor, port->bus_address)) {
			log_error("Unable to create dbus monitor\n");
			return false;
		}

		port->open_for_business = true;
	}

	return true;
}

bool
dbus_bridge_port_connect(dbus_bridge_port_t *port)
{
	char name[64];

	snprintf(name, sizeof(name), "%s-port", port->name);
	port->dbus = dbus_client_new(name, &dbus_impl_bridge, port);
	if (!dbus_client_connect(port->dbus, port->bus_address)) {
		log_error("Unable to create dbus bridge port\n");
		return false;
	}

	port->open_for_business = true;
	return true;
}

bool
dbus_bridge_port_list_names(dbus_bridge_port_t *port)
{
	dbus_client_t *dbus = port->monitor;
	char **registered = NULL;
	int r;

	if (!dbus || !dbus->h) {
		log_debug_id(port->name, "%s: not connected", __func__);
		return false;
	}

	r = sd_bus_list_names(dbus->h, &registered, NULL);
	if (r >= 0) {
		unsigned int count;

		for (count = 0; registered[count]; ++count)
			;

		dbus_debug(dbus, "Found %u registered names", count);
		dbus_bridge_process_registered_names(dbus, (const char **) registered, count);

		{
			char **p;

			for (p = registered; *p; ++p)
				free(*p);
			free(registered);
		}
	}

	return true;
}

bool
dbus_bridge_port_acquire_name(dbus_bridge_port_t *port, const char *name)
{
	dbus_service_proxy_t **pos, *proxy;

	for (pos = &port->service_proxies; (proxy = *pos) != NULL; pos = &proxy->next) {
		if (!strcmp(proxy->name, name)) {
			log_debug("%s: already have a proxy for %s", port->name, name);
			break;
		}
	}

	if (proxy == NULL)
		*pos = proxy = dbus_service_proxy_new(name, port->bus_address);

	if (!dbus_service_proxy_connect(proxy, port)) {
		log_error("Unable to establish a %s proxy connection for %s", port->name, proxy->name);
		return false;
	}

	return true;
}

void
dbus_bridge_port_release_name(dbus_bridge_port_t *port, const char *name)
{
	dbus_service_proxy_t **pos, *proxy;

	for (pos = &port->service_proxies; (proxy = *pos) != NULL; pos = &proxy->next) {
		if (!strcmp(proxy->name, name)) {
			log_debug("%s: deactivating proxy for %s", port->name, name);
			dbus_service_proxy_stop(proxy);
			break;
		}
	}
}

void
dbus_bridge_port_event_name_lost(dbus_bridge_port_t *port, const char *name)
{
	if (port->other == NULL)
		return;

	dbus_bridge_port_release_name(port->other, name);
}

void
dbus_bridge_port_event_name_acquired(dbus_bridge_port_t *port, const char *name)
{
	if (port->other == NULL)
		return;

	if (strutil_array_contains(&port->names_to_publish, name))
		dbus_bridge_port_acquire_name(port->other, name);
}

int
main(int argc, char **argv)
{
	dbus_bridge_port_t *port_upstream, *port_downstream;
	sd_event *event = NULL;

	tracing_set_level(1);

	if (sd_event_default(&event) < 0)
		log_fatal("Unable to create sd-event loop");

	port_upstream = dbus_bridge_port_new("upstream", NULL);
	port_downstream = dbus_bridge_port_new("downstream", "/tmp/downstream");
	port_upstream->other = port_downstream;
	port_downstream->other = port_upstream;

	dbus_bridge_port_publish(port_upstream, "org.freedesktop.NetworkManager");
#if 0
	dbus_bridge_port_publish(port_upstream, "org.fedoraproject.FirewallD1");
	dbus_bridge_port_publish(port_upstream, "net.hadess.PowerProfiles");
#endif
	dbus_bridge_port_publish(port_upstream, "com.intel.tss2.Tabrmd");

	if (1) {
		if (!dbus_bridge_port_monitor(port_downstream, true))
			return 1;
	}

	if (1) {
		if (!dbus_bridge_port_monitor(port_upstream, false))
			return 1;

		dbus_bridge_port_list_names(port_upstream);
	}

	sd_event_loop(event);
	return 0;
}

