/*
 * socket endpoints
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

#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>		/* for offsetof() */
#include <fcntl.h>
#include <errno.h>

#if 0
#include <sys/stat.h>
#include <sys/poll.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>

#include "socket.h"
#endif

#include "endpoint.h"
#include "tracing.h"

socklen_t
socket_make_unix_address(struct sockaddr_un *sun, const char *socket_name)
{
	socklen_t len;

	memset(sun, 0, sizeof(*sun));
	sun->sun_family = AF_LOCAL;

	if (socket_name[0] == '/') {
		/* This is an absolute pathname */
		if (strlen(socket_name) + 1 > sizeof(sun->sun_path)) {
			log_error("socket name \"%s\" too long", socket_name);
			return 0;
		}

		strcpy(sun->sun_path, socket_name);

		len = offsetof(struct sockaddr_un, sun_path) + strlen(sun->sun_path) + 1;
	} else if (socket_name[0] == '@') {
		unsigned int namelen = strlen(socket_name);

		/* This is an abstract socket name */
		if (namelen > sizeof(sun->sun_path)) {
			log_error("socket name \"%s\" too long", socket_name);
			return 0;
		}

		memcpy(sun->sun_path, socket_name, namelen);
		sun->sun_path[0] = '\0';

		len = offsetof(struct sockaddr_un, sun_path) + namelen;
	} else {
		log_error("Bad socket name \"%s\"", socket_name);
		return 0;
	}

	return len;
}

endpoint_t *
endpoint_create_unix_client(const char *socket_name)
{
	struct sockaddr_un sun;
	socklen_t sun_len;
	int fd;

	if ((sun_len = socket_make_unix_address(&sun, socket_name)) == 0)
		return NULL;

	fd = socket(PF_LOCAL, SOCK_STREAM, 0);

	fcntl(fd, F_SETFL, O_NONBLOCK | O_RDWR);

	if (connect(fd, (struct sockaddr *) &sun, sun_len) < 0 && errno != EINPROGRESS) {
		log_error("connect: %m");
		close(fd);
		return NULL;
	}

	return endpoint_new_socket(fd);
}
