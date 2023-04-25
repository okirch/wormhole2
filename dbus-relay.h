/*
 * DBus forwarding support
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
 */

#ifndef _DBUS_RELAY_H
#define _DBUS_RELAY_H

typedef struct dbus_forwarding_port dbus_forwarding_port_t;
typedef struct dbus_forwarder dbus_forwarder_t;

extern dbus_forwarder_t *	dbus_forwarder_new(const char *name);
extern dbus_forwarding_port_t *	dbus_forwarder_get_upstream(dbus_forwarder_t *fwd);
extern dbus_forwarding_port_t *	dbus_forwarder_get_downstream(dbus_forwarder_t *fwd);
extern const char *		dbus_forwarding_port_get_name(const dbus_forwarding_port_t *fwport);
extern void			dbus_forwarding_port_set_bus_name(dbus_forwarding_port_t *fwport, const char *bus_name);
extern void			dbus_forwarding_port_set_socket(dbus_forwarding_port_t *fwport, int fd);
extern void			dbus_forwarder_eventloop(dbus_forwarder_t *fwd);

#endif // _DBUS_RELAY_H
