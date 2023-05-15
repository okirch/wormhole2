/*
 * sysmount.h
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

#ifndef _WORMHOLE_SYSMOUNT_H
#define _WORMHOLE_SYSMOUNT_H

typedef struct fsutil_mount_detail fsutil_mount_detail_t;
struct fsutil_mount_detail {
	unsigned int	refcount;
	char *		fstype;
	char *		fsname;
	char *		options;
	int		flags;
	struct strutil_array overlay_dirs;
};

typedef struct fsutil_mount_req fsutil_mount_req_t;
struct fsutil_mount_req {
	char *			mount_point;
	fsutil_mount_detail_t *	detail;
};

typedef struct fsutil_mount_detail_array {
	unsigned int	count;
	fsutil_mount_detail_t **data;
} fsutil_mount_detail_array_t;

typedef struct fsutil_mount_req_array {
	unsigned int	count;
	fsutil_mount_req_t *data;
} fsutil_mount_req_array_t;

extern fsutil_mount_detail_t *	fsutil_mount_detail_new(const char *fstype, const char *fsname, const char *options);
extern fsutil_mount_detail_t *	fsutil_mount_detail_hold(fsutil_mount_detail_t *md);
extern void			fsutil_mount_detail_release(fsutil_mount_detail_t *md);
extern void			fsutil_mount_detail_array_append(fsutil_mount_detail_array_t *, fsutil_mount_detail_t *);
extern void			fsutil_mount_detail_array_destroy(fsutil_mount_detail_array_t *);

extern void			fsutil_mount_req_destroy(fsutil_mount_req_t *);
extern void			fsutil_mount_req_array_append(fsutil_mount_req_array_t *, const char *mount_point, fsutil_mount_detail_t *);
extern void			fsutil_mount_req_array_destroy(fsutil_mount_req_array_t *);

extern bool			fsutil_mount_overlay(const char *lowerdir,
					const char *upperdir,
					const char *workdir,
					const char *target);
extern bool			fsutil_mount_tmpfs(const char *where);
extern bool			fsutil_mount_bind(const char *source,
					const char *target, bool recursive);
extern bool			fsutil_mount_virtual_fs(const char *where,
					const char *fstype,
					const char *options);
extern bool			fsutil_mount_command(const char *target,
					const char *root_path);
extern bool			fsutil_mount(const char *device,
					const char *target,
					const char *fstype,
					const char *options,
					int flags);
extern bool			fsutil_mount_request(const fsutil_mount_req_t *mr);
extern bool			fsutil_lazy_umount(const char *path);
extern bool			fsutil_make_fs_private(const char *dir, bool maybe_in_chroot);
extern bool			fsutil_same_file(const char *path1, const char *path2);
extern bool			fsutil_dir_is_mountpoint(const char *path);
extern const char *		fsutil_makedir2(const char *parent, const char *name);
extern const char *		fsutil_makefile2(const char *parent, const char *name);
extern bool			fsutil_copy_file(const char *system_path, const char *image_path, const struct stat *st);
extern char *			fsutil_resolve_fsuuid(const char *uuid);
extern bool			fsutil_mount_options_contain(const char *options, const char *word);

enum {
	FSUTIL_MTAB_ITERATOR = 1,
	FSUTIL_FSTAB_ITERATOR,
};

typedef struct fsutil_mount_iterator fsutil_mount_iterator_t;

typedef struct fsutil_mount_cursor {
	const char *		mountpoint;
	fsutil_mount_detail_t *	detail;

	union {
		struct {
			const struct strutil_array *dirs;
		} overlay;
	};
} fsutil_mount_cursor_t;

extern fsutil_mount_iterator_t *fsutil_mount_iterator_create(const char *root_path, int type, const char *mtab);
extern bool			fsutil_mount_iterator_next(fsutil_mount_iterator_t *, fsutil_mount_cursor_t *);
extern void			fsutil_mount_iterator_free(fsutil_mount_iterator_t *);


#endif // _WORMHOLE_SYSMOUNT_H
