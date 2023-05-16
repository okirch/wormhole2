#!/bin/bash
#
# Sample boot-prep script for wormhole
#

/usr/bin/dbus-relay --config /etc/dbus-relay.conf --system-root $WORMHOLE_ROOT -d
