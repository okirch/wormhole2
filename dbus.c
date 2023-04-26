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
#include <sys/time.h>
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

extern bool			dbus_bridge_port_activate_proxy(dbus_bridge_port_t *port, const char *name);
extern void			dbus_bridge_port_event_name_lost(dbus_bridge_port_t *port, const char *name);
extern void			dbus_bridge_port_event_name_acquired(dbus_bridge_port_t *port, const char *name);
static bool			dbus_service_proxy_connect(dbus_service_proxy_t *proxy);

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
	unsigned long		initial_timeout_usec;
	unsigned long		current_timeout_usec;
	struct timeval		expiry_date;
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
	char *			log_name;

	dbus_timer_t *		restart_timer;
	dbus_bridge_port_t *	port;

	bool			enabled;
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

	strutil_drop(&dbus->debug_name);
	strutil_drop(&dbus->bus_name);
	strutil_drop(&dbus->request_name);

	free(dbus);
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

static bool
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

	if (dbus->impl.ops->connection_lost) {
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
 * Helper functions
 */
static void
dbus_free_string_array(char **array)
{
	char **p;

	for (p = array; *p; ++p)
		free(*p);
	free(array);
}

/*
 * Timers
 */
static double dbus_timer_get_remaining(const dbus_timer_t *timer);
static inline void
__dbus_timer_set_expiry(dbus_timer_t *timer, unsigned int timeout_usec)
{
	struct timeval now, delta;

	gettimeofday(&now, NULL);

	delta.tv_sec = timeout_usec / 1000000;
	delta.tv_usec = timeout_usec % 1000000;
	timeradd(&now, &delta, &timer->expiry_date);
}

static int
__dbus_timer_callback(sd_event_source *s, uint64_t usec, void *userdata)
{
	static const unsigned long max_backoff = 30000000; /* 30 seconds */
	dbus_timer_t *timer = userdata;

	if (!timer->callback(timer->userdata)) {
		sd_event_source_set_enabled(timer->event_source, SD_EVENT_OFF);
		return 0;
	}

	if (timer->current_timeout_usec == 0) {
		timer->current_timeout_usec = timer->initial_timeout_usec;
	} else {
		timer->current_timeout_usec <<= 1;
		if (timer->current_timeout_usec > max_backoff)
			timer->current_timeout_usec = max_backoff;
	}

	/* Come back after the specified timeout */
	sd_event_source_set_time_relative(timer->event_source, timer->current_timeout_usec);
	__dbus_timer_set_expiry(timer, timer->current_timeout_usec);
	return 1;
}

static dbus_timer_t *
dbus_timer_new(unsigned long timeout_usec, dbus_timer_callback_fn_t *callback, void *userdata)
{
	dbus_timer_t *timer;
	sd_event *event;

	timer = calloc(1, sizeof(*timer));
	timer->current_timeout_usec = 0;		/* the first time around, the timer will fire immediately */
	timer->initial_timeout_usec = timeout_usec;
	timer->callback = callback;
	timer->userdata = userdata;

	if (sd_event_default(&event) < 0)
		log_fatal("sd_event_default failed");

	sd_event_add_time_relative(event, &timer->event_source, CLOCK_MONOTONIC,
				timer->current_timeout_usec, timeout_usec / 10,
				__dbus_timer_callback, timer);
	__dbus_timer_set_expiry(timer, timer->current_timeout_usec);

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
	__dbus_timer_set_expiry(timer, 0);
	timer->current_timeout_usec = 0;
}

static bool
dbus_timer_is_active(const dbus_timer_t *timer)
{
	int enabled;

	if (sd_event_source_get_enabled(timer->event_source, &enabled) < 0)
		return false;

	return enabled == SD_EVENT_ON;
}

static double
dbus_timer_get_remaining(const dbus_timer_t *timer)
{
	struct timeval now, remain;

	if (!dbus_timer_is_active(timer))
		return 100e6;

	gettimeofday(&now, NULL);
	timersub(&timer->expiry_date, &now, &remain);

	return remain.tv_sec + 1e-6 * remain.tv_usec;
}

/*
 * Create a timer connected to a bridge port
 */
static void
dbus_bridge_add_timer(dbus_bridge_port_t *port, unsigned long timeout_usec, int (*callback)(dbus_bridge_port_t *))
{
	if (port->reconnect_timer == NULL)
		port->reconnect_timer = dbus_timer_new(timeout_usec, (dbus_timer_callback_fn_t *) callback, port);
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

	if (port == NULL)
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
		assert(proxy->port == port);
		if (proxy->enabled && proxy->pid < 0)
			dbus_service_proxy_connect(proxy);
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
dbus_service_proxy_new(dbus_bridge_port_t *port, const char *name)
{
	dbus_service_proxy_t *proxy;
	const char *s;

	proxy = calloc(1, sizeof(*proxy));
	proxy->port = port;
	strutil_set(&proxy->name, name);
	strutil_set(&proxy->bus_address, port->bus_address);
	proxy->pid = -1;

	if ((s = strrchr(name, '.')) != NULL && *(++s) != '\0')
		strutil_set(&proxy->log_name, s);
	else
		strutil_set(&proxy->log_name, name);
	return proxy;
}

static bool
__dbus_service_proxy_configure_port(dbus_service_proxy_t *proxy, dbus_forwarding_port_t *port, dbus_client_t *dbus)
{
	if (dbus == NULL) {
		log_error_id(proxy->log_name, "unable to connect %s", dbus_forwarding_port_get_name(port));
		return false;
	}

	// log_debug_id(proxy->log_name, "Configuring port %s", dbus_forwarding_port_get_name(port));
	dbus_forwarding_port_set_bus_name(port, dbus->bus_name);
	dbus_forwarding_port_set_socket(port, sd_bus_get_fd(dbus->h));
	return true;
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
	snprintf(name, sizeof(name), "%s:%s", proxy->log_name, port->name);
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
dbus_service_proxy_start(dbus_service_proxy_t *proxy)
{
	dbus_bridge_port_t *port = proxy->port;
	dbus_forwarder_t *fwd;
	pid_t pid;

	if (proxy->pid > 0) {
		log_error_id(proxy->name, "we already have an active proxy process");
		return false;
	}

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
	fwd = dbus_forwarder_new(proxy->log_name);

	if (!__dbus_service_proxy_configure_port(proxy, dbus_forwarder_get_upstream(fwd),
			dbus_service_proxy_connect_upstream(proxy, port->other))
	 || !__dbus_service_proxy_configure_port(proxy, dbus_forwarder_get_downstream(fwd),
			dbus_service_proxy_connect_downstream(proxy, port)))
		exit(1);

	dbus_forwarder_eventloop(fwd);

	exit(0);
}

static bool
dbus_service_proxy_connect(dbus_service_proxy_t *proxy)
{
	dbus_bridge_port_t *port = proxy->port;
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
	if (!dbus_service_proxy_start(proxy)) {
		log_error_id(proxy->name, "unable to create forwarding process");
		/* mark this proxy as failed */
	}

	return ok;
}

static void
dbus_service_proxy_add_timer(dbus_service_proxy_t *proxy, unsigned long timeout_usec, int (*callback)(dbus_service_proxy_t *))
{
	if (proxy->restart_timer == NULL) {
		proxy->restart_timer = dbus_timer_new(timeout_usec, (dbus_timer_callback_fn_t *) callback, proxy);
	} else
	if (dbus_timer_is_active(proxy->restart_timer)) {
		/* Do not reset the timer when it's running.
		 * Otherwise, a segfault/bug in the forwarder startup code will result
		 * in us respawning the forwarder in a tight loop. */
		log_debug_id(proxy->log_name, "will retry in %g seconds",
				dbus_timer_get_remaining(proxy->restart_timer));
	} else {
		dbus_timer_restart(proxy->restart_timer);
	}
}

static int
__dbus_service_proxy_restart(dbus_service_proxy_t *proxy)
{
	/* The way this is intended to work is this:
	 *  - we receive SIGCHLD notification that a forwarder died
	 *  - we schedule a timer (so that it fires immediately) and end
	 *    up in this callback.
	 *  - proxy->pid is 0, so we try to restart the forwarder
	 *  - we return 1 to indicate that the timer should be rescheduled.
	 *
	 * If the forwarder starts up OK, proxy->pid will still hold a valid PID
	 * by the time we return here. In this case, we declare victory and
	 * stop the timer.
	 *
	 * If the forwarder dies during startup:
	 *  - we receive another SIGCHLD, and clear proxy->pid. We do not
	 *    restart the timer
	 *  - when the timer fires eventually, we will come back here,
	 *    and try restart the forwarder again.
	 *  - we return 1 so that the timer is rescheduled, with exponential
	 *    backoff.
	 */
	if (proxy->pid > 0) {
		log_debug_id(proxy->log_name, "forwarder startup was successful");
		return 0;
	}

	(void) dbus_service_proxy_connect(proxy);
	return 1;
}

static void
dbus_service_proxy_attempt_restart(dbus_service_proxy_t *proxy)
{
	dbus_service_proxy_add_timer(proxy, 1000000, __dbus_service_proxy_restart);
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
		dbus_free_string_array(registered);
	}

	return true;
}

static dbus_service_proxy_t *
__dbus_bridge_port_get_proxy(dbus_bridge_port_t *port, const char *name, bool create)
{
	dbus_service_proxy_t **pos, *proxy;

	for (pos = &port->service_proxies; (proxy = *pos) != NULL; pos = &proxy->next) {
		if (!strcmp(proxy->name, name))
			return proxy;
	}

	if (proxy == NULL && create)
		*pos = proxy = dbus_service_proxy_new(port, name);

	return proxy;
}

static dbus_service_proxy_t *
dbus_bridge_port_create_proxy(dbus_bridge_port_t *port, const char *name)
{
	return __dbus_bridge_port_get_proxy(port, name, true);
}

static dbus_service_proxy_t *
dbus_bridge_port_find_proxy(dbus_bridge_port_t *port, const char *name)
{
	return __dbus_bridge_port_get_proxy(port, name, false);
}

static dbus_service_proxy_t *
dbus_bridge_port_find_proxy_by_pid(dbus_bridge_port_t *port, pid_t pid)
{
	dbus_service_proxy_t *proxy;

	for (proxy = port->service_proxies; proxy != NULL; proxy = proxy->next) {
		if (proxy->pid == pid)
			return proxy;
	}

	return NULL;
}

bool
dbus_bridge_port_activate_proxy(dbus_bridge_port_t *port, const char *name)
{
	dbus_service_proxy_t *proxy;

	if (!(proxy = dbus_bridge_port_find_proxy(port, name)))
		return false;

	proxy->enabled = true;
	if (!dbus_service_proxy_connect(proxy)) {
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
			log_debug("%s: disabling proxy for %s", port->name, name);
			proxy->enabled = false;
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
	dbus_bridge_port_t *downstream;

	if ((downstream = port->other) == NULL)
		return;

	dbus_bridge_port_activate_proxy(downstream, name);
}

/*
 * Handle child processes that exit
 */
static int
handle_sigchld(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata)
{
	dbus_bridge_port_t *port = userdata;
	dbus_service_proxy_t *proxy;
	const char *desc = "terminated";
	int status;

	log_debug("received signal %d from pid %d", si->ssi_signo, si->ssi_pid);
	if (waitpid(si->ssi_pid, &status, 0) >= 0)
		desc = procutil_child_status_describe(status);

	if ((proxy = dbus_bridge_port_find_proxy_by_pid(port, si->ssi_pid)) != NULL) {
		log_debug_id(proxy->log_name, "relay process %s", desc);
		proxy->pid = -1;

		if (proxy->enabled)
			dbus_service_proxy_attempt_restart(proxy);
	}

	return 0;
}

static bool
install_sigchld_handler(dbus_bridge_port_t *port)
{
	sd_event *event = NULL;
	sigset_t set;
	int r;

	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	sigprocmask(SIG_BLOCK, &set, NULL);

	if (sd_event_default(&event) < 0)
		log_fatal("Unable to create sd-event loop");

	r = sd_event_add_signal(event, NULL, SIGCHLD, handle_sigchld, port);
	if (r < 0) {
		log_debug("sd_event_add_signal() = %s", strerror(-r));
		return false;
	}

	return true;
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

	dbus_bridge_port_create_proxy(port_downstream, "org.freedesktop.NetworkManager");
#if 0
	dbus_bridge_port_create_proxy(port_downstream, "org.fedoraproject.FirewallD1");
	dbus_bridge_port_create_proxy(port_downstream, "net.hadess.PowerProfiles");
#endif
	dbus_bridge_port_create_proxy(port_downstream, "com.intel.tss2.Tabrmd");

	if (!install_sigchld_handler(port_downstream))
		return 1;

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

