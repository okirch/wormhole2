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

static bool
__get_mount_state(const char *mtab, const char *root_dir,
		bool (*report_fn)(void *user_data,
				const char *mount_point,
				const char *mnt_type,
				const char *fsname),
		void *user_data)
{
	FILE *mf;
	struct mntent *m;
	char root_path_buf[PATH_MAX];
	bool okay = true;

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

	while (okay && (m = getmntent(mf)) != NULL) {
		const char *mount_point = m->mnt_dir;

		if (root_dir) {
			const char *relative_path;

			relative_path = fsutil_strip_path_prefix(mount_point, root_dir);
			if (relative_path == NULL) {
				trace("%s is not below %s", m->mnt_dir, root_dir);
				continue;
			}
			mount_point = relative_path;
		}

		if (!report_fn(user_data, mount_point, m->mnt_type, m->mnt_fsname)) {
			log_error("Something is wrong with %s\n", m->mnt_dir);
			okay = false;
		}
	}

	endmntent(mf);

	return okay;
}

bool
mount_state_discover(const char *mtab,
		bool (*report_fn)(void *user_data,
				const char *mount_point,
				const char *mnt_type,
				const char *fsname),
		void *user_data)
{
	return __get_mount_state(mtab, NULL, report_fn, user_data);
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
