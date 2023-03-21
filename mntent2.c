/*
 * Inspect /proc/mounts
 *
 *   Copyright (C) 2020-2021 Olaf Kirch <okir@suse.de>
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

#include <sys/stat.h>
#include <stdio.h>
#include <mntent.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "wormhole2.h"
#include "tracing.h"
#include "util.h"


struct fsutil_mount_iterator {
	FILE *		mf;
	char *		root_dir;

	struct strutil_array overlay_dirs;
};

fsutil_mount_iterator_t *
fsutil_mount_iterator_create(const char *root_dir, const char *mtab)
{
	fsutil_mount_iterator_t *it;
	char root_path_buf[PATH_MAX];
	FILE *mf;

	if (mtab == NULL)
		mtab = "/proc/mounts";

	if (root_dir) {
		const char *resolved_root;

		resolved_root = realpath(root_dir, root_path_buf);
		if (resolved_root == NULL) {
			log_error("realname(%s) failed: %m", root_dir);
			return NULL;
		}

		root_dir = resolved_root;
	}

	if ((mf = setmntent(mtab, "r")) == NULL) {
		log_error("Unable to open %s: %m", mtab);
		return NULL;
	}

	it = calloc(1, sizeof(*it));
	strutil_set(&it->root_dir, root_dir);
	it->mf = mf;

	return it;
}

void
fsutil_mount_iterator_free(fsutil_mount_iterator_t *it)
{
	strutil_array_destroy(&it->overlay_dirs);
	strutil_drop(&it->root_dir);

	if (it->mf) {
		endmntent(it->mf);
		it->mf = NULL;
	}

	free(it);
}

static const struct strutil_array *
__process_overlay_options(fsutil_mount_iterator_t *it, const char *options)
{
	char *copy, *s, *upper = NULL, *lower = NULL, *colon;

	if (options == NULL)
		return NULL;

	strutil_array_destroy(&it->overlay_dirs);

	copy = strdup(options);
	for (s = strtok(copy, ","); s; s = strtok(NULL, ",")) {
		if (!strncmp(s, "upperdir=", 9))
			upper = s + 9;
		else if (!strncmp(s, "lowerdir=", 9))
			lower = s + 9;
	}

	if (lower) {
		while ((colon = strrchr(lower, ':')) != NULL) {
			*colon++ = '\0';
			strutil_array_append(&it->overlay_dirs, colon);
		}
		strutil_array_append(&it->overlay_dirs, lower);
	}
	if (upper)
		strutil_array_append(&it->overlay_dirs, upper);

	return &it->overlay_dirs;
}

bool
fsutil_mount_iterator_next(fsutil_mount_iterator_t *it, fsutil_mount_cursor_t *cursor)
{
	struct mntent *m;

	memset(cursor, 0, sizeof(*cursor));

	if (!it->mf)
		return false;

	strutil_array_destroy(&it->overlay_dirs);

	while ((m = getmntent(it->mf)) != NULL) {
		const char *mount_point = m->mnt_dir;

		if (it->root_dir) {
			const char *relative_path;

			relative_path = fsutil_strip_path_prefix(mount_point, it->root_dir);
			if (relative_path == NULL) {
				trace("%s is not below %s", m->mnt_dir, it->root_dir);
				continue;
			}
			mount_point = relative_path;
		}

		cursor->mountpoint = mount_point;
		cursor->fstype = m->mnt_type;
		cursor->fsname = m->mnt_fsname;
		cursor->options = m->mnt_opts;

		if (!strcmp(cursor->fstype, "overlay"))
			cursor->overlay.dirs = __process_overlay_options(it, cursor->options);

		return true;
	}

	return false;
}

bool
fsutil_dir_is_mountpoint(const char *path)
{
	struct stat stb1, stb2;
	FILE *mf;
	struct mntent *m;
	bool is_mount = false;

	if (stat(path, &stb1) < 0)
		return false;

	if ((mf = setmntent("/proc/mounts", "r")) == NULL) {
		log_error("Unable to open /proc/mounts: %m");
		return false;
	}

	while (!is_mount && (m = getmntent(mf)) != NULL) {
		if (stat(m->mnt_dir, &stb2) >= 0) {
			is_mount = (stb1.st_dev == stb2.st_dev)
			       &&  (stb1.st_ino == stb2.st_ino);
		}
	}
	endmntent(mf);

	return is_mount;
}
