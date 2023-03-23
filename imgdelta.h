/*
 * imgdelta
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


#ifndef IMGDELTA_H
#define IMGDELTA_H

#include "wormhole2.h"
#include "util.h"

struct imgdelta_config {
	unsigned int		debug;
	bool			force;
	bool			create_base_layer;
	bool			running_inside_chroot;
	unsigned int		ignore_change_mask;
	char *			install_bindir;

	struct wormhole_layer *	layer;

	struct strutil_array	layers_used;
	struct strutil_array	layer_images;

	struct mount_config_array mounts;

	struct strutil_array	excldirs;

	struct strutil_array	entry_points;
	strutil_mapping_t	entry_point_symlinks;
};

#endif /* IMGDELTA_H */
