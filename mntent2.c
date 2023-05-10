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

static bool		fsutil_mount_iterator_getmntent(fsutil_mount_iterator_t *it, fsutil_mount_cursor_t *cursor);

struct fsutil_mount_iterator {
	FILE *		mf;
	int		type;
	char *		strip_prefix;
	struct strutil_array overlay_dirs;
};

static fsutil_mount_iterator_t *
fsutil_mount_iterator_new(const char *root_dir, int type)
{
	char root_path_buf[PATH_MAX];
	fsutil_mount_iterator_t *it;

	it = calloc(1, sizeof(*it));
	it->type = type;

	/* When searching /proc/mounts for entries below a certain root directory,
	 * we need to resolve the root dir to its realpath, as this is what
	 * /proc/mounts will show. */
	if (root_dir && type == FSUTIL_MTAB_ITERATOR) {
		const char *resolved_root;

		resolved_root = realpath(root_dir, root_path_buf);
		if (resolved_root == NULL) {
			log_error("realname(%s) failed: %m", root_dir);
			fsutil_mount_iterator_free(it);
			return NULL;
		}

		strutil_set(&it->strip_prefix, resolved_root);
	}

	return it;
}

fsutil_mount_iterator_t *
fsutil_mount_iterator_create(const char *root_dir, int type, const char *xtab_path)
{
	fsutil_mount_iterator_t *it;

	it = fsutil_mount_iterator_new(root_dir, type);

	switch (type) {
	case FSUTIL_MTAB_ITERATOR:
		if (xtab_path == NULL)
			xtab_path = "/proc/mounts";

		it->mf = setmntent(xtab_path, "r");
		break;

	case FSUTIL_FSTAB_ITERATOR:
		if (xtab_path == NULL)
			xtab_path = "/etc/fstab";

		if (root_dir)
			xtab_path = __pathutil_concat2(root_dir, xtab_path);

		it->mf = fopen(xtab_path, "r");
		break;

	default:
		log_error("%s: unknown type %u", __func__, type);
		return false;
	}

	if (it->mf == NULL) {
		log_error("Unable to open %s: %m", xtab_path);
		fsutil_mount_iterator_free(it);
		return NULL;
	}

	return it;
}

static void
fsutil_mount_iterator_close(fsutil_mount_iterator_t *it)
{
	if (it->mf) {
		endmntent(it->mf);
		it->mf = NULL;
	}
}

bool
fsutil_mount_iterator_next(fsutil_mount_iterator_t *it, fsutil_mount_cursor_t *cursor)
{
	memset(cursor, 0, sizeof(*cursor));

	if (!it->mf)
		return false;

	strutil_array_destroy(&it->overlay_dirs);
	if (!fsutil_mount_iterator_getmntent(it, cursor)) {
		fsutil_mount_iterator_close(it);
		return false;
	}

	return true;
}

void
fsutil_mount_iterator_free(fsutil_mount_iterator_t *it)
{
	fsutil_mount_iterator_close(it);
	strutil_array_destroy(&it->overlay_dirs);
	strutil_drop(&it->strip_prefix);
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

static void
fsutil_mount_cursor_set(struct fsutil_mount_iterator *it, fsutil_mount_cursor_t *cursor, const char *mount_point, const char *fstype, const char *fsname, const char *options)
{
	if (options && !strcmp(options, "defaults"))
		options = NULL;

	cursor->mountpoint = mount_point;
	cursor->fstype = fstype;
	cursor->fsname = fsname;
	cursor->options = options;

	if (!strcmp(cursor->fstype, "overlay"))
		cursor->overlay.dirs = __process_overlay_options(it, cursor->options);
}

static inline const char *
maybe_strip_root_dir(const char *mount_point, const char *strip_prefix)
{
	const char *relative_path;

	if (strip_prefix == NULL)
		return mount_point;

	relative_path = fsutil_strip_path_prefix(mount_point, strip_prefix);
	if (relative_path == NULL) {
		trace("%s is not below %s", mount_point, strip_prefix);
		return NULL;
	}

	return relative_path;
}

static bool
fsutil_mount_iterator_getmntent(fsutil_mount_iterator_t *it, fsutil_mount_cursor_t *cursor)
{
	struct mntent *m;

	while ((m = getmntent(it->mf)) != NULL) {
		const char *mount_point = m->mnt_dir;

		if (!(mount_point = maybe_strip_root_dir(mount_point, it->strip_prefix)))
			continue;

		fsutil_mount_cursor_set(it, cursor, mount_point, m->mnt_type, m->mnt_fsname, m->mnt_opts);
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

/*
 * mount details as found in fstab and mtab
 * FIXME: these don't really belong here.
 */
fsutil_mount_detail_t *
fsutil_mount_detail_new(const char *fstype, const char *fsname, const char *options)
{
	fsutil_mount_detail_t *md;

	md = calloc(1, sizeof(*md));

	md->refcount = 1;
	strutil_set(&md->fstype, fstype);
	strutil_set(&md->fsname, fsname);
	strutil_set(&md->options, options);

	return md;
}

fsutil_mount_detail_t *
fsutil_mount_detail_hold(fsutil_mount_detail_t *md)
{
	if (md != NULL) {
		if (!md->refcount)
			log_fatal("%s: refcount == 0", __func__);
		md->refcount += 1;
	}
	return md;
}

void
fsutil_mount_detail_release(fsutil_mount_detail_t *md)
{
	if (!md->refcount)
		log_fatal("%s: refcount == 0", __func__);

	if (--(md->refcount))
		return;

	strutil_drop(&md->fstype);
	strutil_drop(&md->fsname);
	strutil_drop(&md->options);
	strutil_array_destroy(&md->overlay_dirs);
	free(md);
}
