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

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <assert.h>

#include "imgdelta.h"
#include "wormhole2.h"
#include "tracing.h"

#define CMP_TYPE_CHANGED	0x0001
#define CMP_MODE_CHANGED	0x0002
#define CMP_CONTENT_CHANGED	0x0004
#define CMP_OWNER_CHANGED	0x0008
#define CMP_MTIME_CHANGED	0x0010

static bool		can_chown = false;
static const char *	default_copydirs[] = {
	"/bin",
	"/sbin",
	"/lib",
	"/lib64",
	"/usr",
	NULL,
};

static const struct stat *
do_stat(const char *path, struct stat *stb)
{
	if (lstat(path, stb) < 0) {
		log_error("%s: cannot stat: %m", path);
		return NULL;
	}

	return stb;
}

static inline unsigned int
detect_changes(const char *patha, const struct stat *sta, const char *pathb, const struct stat *stb)
{
	unsigned long mode_xor;
	int bits_changed = 0;

	mode_xor = sta->st_mode ^ stb->st_mode;
	if (mode_xor & S_IFMT) {
		trace3("%s: file type changed", patha);
		return ~0; /* type changed, update everything */
	}

	if (mode_xor != 0) {
		trace3("%s: mode changed 0%o -> 0%o", patha, sta->st_mode, stb->st_mode);
		bits_changed |= CMP_MODE_CHANGED;
	}

	switch (stb->st_mode & S_IFMT) {
	case S_IFREG:
		if (sta->st_size != stb->st_size) {
			trace3("%s: size changed %lu -> %lu", patha, (long) sta->st_size, (long) stb->st_size);
			bits_changed |= CMP_CONTENT_CHANGED;
		} else
		if (!fsutil_file_content_identical(patha, pathb)) {
			trace3("%s: file content changed", patha);
			bits_changed |= CMP_CONTENT_CHANGED;
		}

		if (sta->st_mtim.tv_sec != stb->st_mtim.tv_sec
		 || sta->st_mtim.tv_nsec / 1000 != stb->st_mtim.tv_nsec / 1000) {
			trace3("%s: mtime changed %lu.%09lu -> %lu.%09lu", patha,
					(long) sta->st_mtim.tv_sec,
					(long) sta->st_mtim.tv_nsec,
					(long) stb->st_mtim.tv_sec,
					(long) stb->st_mtim.tv_nsec);
			bits_changed |= CMP_MTIME_CHANGED;
		}
		break;

	case S_IFLNK:
		{
			char targeta[PATH_MAX], targetb[PATH_MAX];
			int lena, lenb;

			if ((lena = readlink(pathb, targetb, sizeof(targetb))) < 0
			 || (lenb = readlink(patha, targeta, sizeof(targeta))) < 0
			 || lena != lenb
			 || strncmp(targeta, targetb, lena)) {
				trace3("%s: symlink target changed %s -> %s", patha, targeta, targetb);
				bits_changed |= CMP_CONTENT_CHANGED;
			}
		}
		break;
	}

	if (can_chown
	 && sta->st_uid != stb->st_uid
	 && sta->st_gid != stb->st_gid) {
		trace3("%s: owner changed from %u:%u -> %u:%u", patha,
				(int) sta->st_uid,
				(int) sta->st_gid,
				(int) stb->st_uid,
				(int) stb->st_gid);
		bits_changed |= CMP_OWNER_CHANGED;
	}

	return bits_changed;
}

static bool
__image_update_attrs(const char *image_path, const struct stat *stb)
{
	const char *dir_path, *base_name;
	int dirfd;

	dir_path = pathutil_dirname(image_path);
	base_name = basename(image_path);
	if ((dirfd = open(dir_path, O_RDONLY|O_NOCTTY|O_NONBLOCK|O_NOFOLLOW|O_DIRECTORY)) < 0) {
		log_error("unable to open %s: %m", dir_path);
		return false;
	}

	if (can_chown && fchownat(dirfd, base_name, stb->st_uid, stb->st_gid, AT_SYMLINK_NOFOLLOW) < 0) {
		log_error("%s: cannot set owner %u:%u: %m", image_path, stb->st_uid, stb->st_gid);
		return false;
	}

	/* As of this writing, fchmodat does not support AT_SYMLINK_NOFOLLOW.
	 * Hence we only make an attempt to change the mode for files other than symlinks */
	if (!S_ISLNK(stb->st_mode)) {
		if (fchmodat(dirfd, base_name, stb->st_mode & 0777, 0) < 0)
			log_warning("%s: cannot set mode 0%03o: %m", image_path, stb->st_mode & 0777);
	}

	if (1) {
		struct timespec ut[2];

		ut[0] = stb->st_atim;
		ut[1] = stb->st_mtim;

		trace2("%s: changing mtime -> %lu.%09lu", image_path,
				(long) ut[1].tv_sec,
				(long) ut[1].tv_nsec);
		if (utimensat(dirfd, base_name, ut, AT_SYMLINK_NOFOLLOW) < 0)
			log_warning("%s: cannot set atime and mtime: %m", image_path);
	}

	/* copy SELinux context? */

	close(dirfd);
	return true;
}

static bool
__image_copy(const char *image_root, const char *src_path, const char *relative_src_path, int dt_type, const struct stat *st, unsigned int change_hints)
{
	const char *image_path;
	struct stat _stb;

	trace3("copy %s -> %s%s", src_path, image_root, relative_src_path);
	if (st == NULL && !(st = do_stat(src_path, &_stb)))
		return false;

	image_path = __pathutil_concat2(image_root, relative_src_path);
	if (dt_type == DT_DIR) {
		mode_t mode = st->st_mode;

		trace2("create dir %s", image_path);

		/* This may not the the right place. Maybe we should do this as a post-processing step.
		 * The only case where we really need to change a directory's permission is if we want
		 * to mount something on top of it. OTOH, how do we really know which directories will
		 * end up being used as mount points? */
		if ((mode ^ 0055) & 0055) {
			log_info("%s: directory has mode 0%o, changing to 0%o", src_path, mode, mode | 0055);
			if (st != &_stb) {
				_stb = *st;
				st = &_stb;
			}
			_stb.st_mode |= 055;
		}

		if (!fsutil_makedirs(image_path, st->st_mode)) {
			log_error("%s: cannot create directory: %m", image_path);
			return false;
		}
	} else
	if (dt_type == DT_REG) {
		if (change_hints & CMP_CONTENT_CHANGED) {
			trace2("copy regular file %s", image_path);
			if (!fsutil_copy_file(src_path, image_path, st))
				return false;
		}
	} else
	if (dt_type == DT_LNK) {
		char target[PATH_MAX + 1];
		ssize_t len;

		len = readlink(src_path, target, sizeof(target) - 1);
		if (len < 0) {
			log_error("%s: readlink failed: %m", src_path);
			return false;
		}
		target[len] = '\0';

		(void) unlink(image_path);
		trace2("create symlink %s -> %s", image_path, target);
		if (symlink(target, image_path) < 0) {
			log_error("%s: unable to create symlink to: %m", image_path, target);
			return false;
		}
	} else
	if (dt_type == DT_CHR || dt_type == DT_BLK) {
		trace2("create device %s", image_path);
		if (mknod(image_path, st->st_mode, st->st_rdev) < 0) {
			log_error("%s: unable to create device node: %m", image_path);
			return false;
		}
	} else
	if (dt_type == DT_FIFO) {
		trace2("create sock %s", image_path);
		if (mkfifo(image_path, st->st_mode) < 0) {
			log_error("%s: unable to create FIFO: %m", image_path);
			return false;
		}
	} else
	if (dt_type == DT_SOCK || dt_type == DT_WHT) {
		trace("%s: ignoring this type of file", src_path);
		return true;
	} else {
		log_error("%s: dirent type %u not yet implemented", src_path, dt_type);
		return false;
	}

	return __image_update_attrs(image_path, st);
}

static bool
image_copy(const char *image_root, struct fsutil_ftw_cursor *cursor)
{
	const struct stat *st;
	struct stat stb;

	assert(cursor);
	if ((st = cursor->st) == NULL) {
		if (lstat(cursor->path, &stb) < 0) {
			log_error("cannot stat %s: %m", cursor->path);
			return false;
		}
		st = &stb;
	}

	return __image_copy(image_root, cursor->path, cursor->relative_path, cursor->d->d_type, st, ~0);
}

static bool
image_compare_copy(struct imgdelta_config *cfg, const char *image_root, struct fsutil_ftw_cursor *cursor)
{
	const char *image_path;
	struct stat image_stb;
	unsigned int bits_changed;

	assert(cursor && cursor->st);

	image_path = __pathutil_concat2(image_root, cursor->path);
	if (do_stat(image_path, &image_stb)) {
		bits_changed = detect_changes(cursor->path, cursor->st, image_path, &image_stb);
		bits_changed &= ~(cfg->ignore_change_mask);
		if (bits_changed == 0) {
			trace3("%s: unchanged", cursor->path);
			return true;
		}
	}

	trace("update %c%c%c%c%c %s",
			(bits_changed & CMP_TYPE_CHANGED)? 'X' : '-',
			(bits_changed & CMP_MODE_CHANGED)? 'M' : '-',
			(bits_changed & CMP_CONTENT_CHANGED)? 'C' : '-',
			(bits_changed & CMP_OWNER_CHANGED)? 'O' : '-',
			(bits_changed & CMP_MTIME_CHANGED)? 'T' : '-',
			cursor->path);
	return __image_copy(image_root, cursor->path, cursor->relative_path, cursor->d->d_type, cursor->st, bits_changed);
}

static bool
image_remove(const char *image_root, struct fsutil_ftw_cursor *cursor)
{
	const char *image_path = cursor->path;
	struct stat stb;

	trace("%s(%s)", __func__, image_path);
	if (!do_stat(image_path, &stb))
		return false;

	switch (stb.st_mode & S_IFMT) {
	case S_IFREG:
	case S_IFLNK:
	case S_IFCHR:
	case S_IFBLK:
	case S_IFSOCK:
		if (unlink(image_path) < 0) {
			log_error("%s: unlink failed: %m", image_path);
			return false;
		}
		break;

	case S_IFDIR:
		if (!fsutil_remove_recursively(image_path))
			return false;
		break;

	default:
		log_error("%s: file type not supported", image_path);
		return false;
	}

	return true;
}

bool
copy_recursively(const char *src_path, const char *dst_path)
{
        struct fsutil_ftw_ctx *ctx;
        struct fsutil_ftw_cursor cursor;
	bool ok = true;

	if (!fsutil_makedirs(dst_path, 0755))
		return false;

	ctx = fsutil_ftw_open("/", FSUTIL_FTW_NEED_STAT, src_path);
	if (mkdir(dst_path, 0755) < 0 && errno != EEXIST) {
		log_error("%s: cannot create directory: %m", dst_path);
		return false;
	}

        while (fsutil_ftw_next(ctx, &cursor)) {
		char dst[PATH_MAX];

		snprintf(dst, sizeof(dst), "%s/%s", dst_path, cursor.relative_path);
		ok = image_copy(dst_path, &cursor) && ok;
        }

	fsutil_ftw_ctx_free(ctx);
	return ok;
}

static int
update_image_partial(struct imgdelta_config *cfg, const char *image_root, const char *dir_path)
{
	const struct strutil_array *exclude = &cfg->excldirs;
	struct fsutil_ftw_ctx *system_ctx;
	struct fsutil_ftw_ctx *image_ctx;
	struct fsutil_ftw_cursor system_cursor;
	struct fsutil_ftw_cursor image_cursor;
	unsigned int i;
	bool ok = true;

	/* This is a hack - we need it until fsutil_ftw returns the top-level
	 * directory as well. */
	{
		struct stat stb;
		int dt_type;

		if (strutil_array_contains(exclude, dir_path))
			goto done;

		if (!do_stat(dir_path, &stb))
			goto failed;

		dt_type = __fsutil_get_dtype(&stb);
		if (!__image_copy(image_root, dir_path, dir_path, dt_type, &stb, ~0))
			goto failed;

		if (!S_ISDIR(stb.st_mode))
			goto done;
	}

	system_ctx = fsutil_ftw_open(dir_path, FSUTIL_FTW_SORTED | FSUTIL_FTW_NEED_STAT, NULL);
	if (system_ctx == NULL) {
		log_error("Cannot open %s", dir_path);
		return false;
	}

	for (i = 0; i < exclude->count; ++i)
		fsutil_ftw_exclude(system_ctx, exclude->data[i]);

	memset(&system_cursor, 0, sizeof(system_cursor));
	memset(&image_cursor, 0, sizeof(image_cursor));

	image_ctx = fsutil_ftw_open(dir_path, FSUTIL_FTW_SORTED, image_root);
	if (image_ctx == NULL) {
		log_error("Cannot open %s%s", image_root, dir_path);
		return false;
	}

	while (true) {
		int r;

		if (!system_cursor.d && !fsutil_ftw_next(system_ctx, &system_cursor))
			break;
		if (!image_cursor.d && !fsutil_ftw_next(image_ctx, &image_cursor))
			break;

		trace3("%s vs %s", system_cursor.path, image_cursor.path);
		r = strcmp(system_cursor.path, image_cursor.relative_path);
		if (r == 0) {
			ok = image_compare_copy(cfg, image_root, &system_cursor) && ok;
			system_cursor.d = NULL;
			image_cursor.d = NULL;
		} else
		if (r < 0) {
			trace("%s: added to system", system_cursor.path);
			ok = image_copy(image_root, &system_cursor) && ok;
			system_cursor.d = NULL;
		} else {
			trace("%s: removed from system", image_cursor.relative_path);
			ok = image_remove(image_root, &image_cursor) && ok;
			fsutil_ftw_skip(image_ctx, &image_cursor);
			image_cursor.d = NULL;
		}
	}

	while (system_cursor.d) {
		trace("%s: added to system", system_cursor.path);
		ok = image_copy(image_root, &system_cursor) && ok;
		fsutil_ftw_next(system_ctx, &system_cursor);
	}

	while (image_cursor.d) {
		trace("%s: removed from system", image_cursor.path);
		ok = image_remove(image_root, &image_cursor) && ok;
		fsutil_ftw_skip(image_ctx, &image_cursor);
		fsutil_ftw_next(image_ctx, &image_cursor);
	}

done:
	if (!ok)
		return 1;

	return 0;

failed:
	/* FIXME: cleanup */
	return 1;
}

static int
update_image_work(struct imgdelta_config *cfg, const char *tpath)
{
	char upperdir[PATH_MAX], workdir[PATH_MAX], overlay[PATH_MAX];
	char *lowerspec;
	unsigned int i;
	int rv;

	if (cfg->create_base_layer) {
		char empty[PATH_MAX];

		/* should have been checked in main() */
		assert(cfg->layer_images.count == 0);

		snprintf(empty, sizeof(empty), "%s/empty", tpath);
		if (mkdir(empty, 0755) < 0) {
			log_error("canot create empty directory: %m");
			return 1;
		}
		strutil_array_append(&cfg->layer_images, empty);
	} else {
		struct wormhole_layer_array resolved = { 0 };
		/* FIXME: remount layers to shorten the path names? */
		const char *remount_image_base = NULL; 

		if (!wormhole_layers_resolve(&resolved, &cfg->layers_used, remount_image_base))
			return 1;

		for (i = 0; i < resolved.count; ++i)
			strutil_array_append(&cfg->layer_images, resolved.data[i]->image_path);

		wormhole_layer_array_destroy(&resolved);
	}

	lowerspec = strutil_array_join(&cfg->layer_images, ":");

	snprintf(workdir, sizeof(workdir), "%s/work", tpath);
	if (mkdir(workdir, 0755) < 0) {
		log_error("canot create work directory: %m");
		return 1;
	}

	snprintf(upperdir, sizeof(upperdir), "%s/delta", tpath);
	if (mkdir(upperdir, 0755) < 0) {
		log_error("canot create delta directory: %m");
		return 1;
	}

	snprintf(overlay, sizeof(overlay), "%s/root", tpath);
	if (mkdir(overlay, 0755) < 0) {
		log_error("canot create root directory: %m");
		return 1;
	}

	if (!fsutil_mount_overlay(lowerspec, upperdir, workdir, overlay))
		return 1;

	trace("=== Building image delta between system and %s ===", overlay);
	for (i = 0; i < cfg->stacked_mounts.count; ++i) {
		const char *dir_path = cfg->stacked_mounts.data[i];

		rv = update_image_partial(cfg, overlay, dir_path);
		if (rv != 0)
			return rv;
	}

	if (cfg->transparent_mounts.count) {
		trace("=== Creating empty directories ===");

		for (i = 0; i < cfg->transparent_mounts.count; ++i) {
			const char *dir_path = cfg->transparent_mounts.data[i];

			if (!fsutil_makedirs(__pathutil_concat2(overlay, dir_path), 0755))
				rv = 1;
		}

		if (rv)
			return rv;
	}

	trace("=== Recursively copying image delta to %s ===", cfg->layer->image_path);
	if (!copy_recursively(upperdir, cfg->layer->image_path))
		return 1;

	/* If the config calls out any entry points, add them to the layer config
	 * so that the corresponding wrapper scripts get created in layer/bin */
	strutil_array_append_array(&cfg->layer->entry_points, &cfg->entry_points);

	return 0;
}

static int
update_image(struct imgdelta_config *cfg)
{
	struct fsutil_tempdir tempdir;
	mode_t old_umask;
	int rv;

	/* Set the umask to 0 for all files and dirs we create. */
	old_umask = umask(0);

	fsutil_tempdir_init(&tempdir);

	trace("=== Initialiting namespace ===");
	if (geteuid() == 0) {
		if (!wormhole_create_namespace())
			return 1;
	} else {
		if (!wormhole_create_user_namespace(true))
			return 1;
	}

	if (!fsutil_make_fs_private("/", cfg->running_inside_chroot))
		return 1;

	if (!fsutil_tempdir_mount(&tempdir))
		return 1;

	rv = update_image_work(cfg, fsutil_tempdir_path(&tempdir));

	fsutil_tempdir_cleanup(&tempdir);
	umask(old_umask);
	return rv;
}

static struct mount_farm *
create_mount_farm_for_layer(struct wormhole_layer *layer, struct imgdelta_config *cfg)
{
	struct mount_farm *farm;
	unsigned int i;

	farm = mount_farm_new(layer->image_path);

	for (i = 0; i < cfg->transparent_mounts.count; ++i) {
		const char *dir_path = cfg->transparent_mounts.data[i];

		if (!mount_farm_add_transparent(farm, dir_path, layer))
			goto failed;
	}

	for (i = 0; i < cfg->stacked_mounts.count; ++i) {
		const char *dir_path = cfg->stacked_mounts.data[i];

		/* For non-root layers, only include directories if they're non-empty */
		/* FIXME: it would be better to move this check to a later stage. If we
		 * do it here, we may miss some consistency problems. */
		if (!layer->is_root) {
			const char *full_path = __pathutil_concat2(layer->image_path, dir_path);

			if (!fsutil_exists(full_path) || fsutil_dir_is_empty(full_path)) {
				trace("layer %s does not provide %s", layer->name, dir_path);
				continue;
			}
		}

		if (!mount_farm_add_stacked(farm, dir_path, layer))
			goto failed;
	}

	return farm;

failed:
	mount_farm_free(farm);
	return NULL;
}

static bool
__update_layer_config(struct wormhole_layer *layer, struct imgdelta_config *cfg)
{
	struct mount_farm *farm;
	unsigned int i;

	layer->is_root = cfg->create_base_layer;
	if (!cfg->create_base_layer)
		strutil_array_append_array(&layer->used, &cfg->layers_used);

	if (!(farm = create_mount_farm_for_layer(layer, cfg)))
		return false;

	if (tracing_level > 1)
		mount_farm_print_tree(farm);

	wormhole_layer_update_from_mount_farm(layer, farm->tree->root);
	mount_farm_free(farm);

	for (i = 0; i < cfg->entry_point_symlinks.count; ++i) {
		struct strutil_mapping_pair *link = &cfg->entry_point_symlinks.data[i];

		wormhole_layer_add_entry_point_symlink(layer, link->key, link->value);
	}

	return true;
}

static int
write_layer_config(struct imgdelta_config *cfg)
{
	__update_layer_config(cfg->layer, cfg);
	if (!wormhole_layer_save_config(cfg->layer))
		return 1;

	return 0;
}

enum {
	OPT_BINDIR = 256,
};

static struct option	long_options[] = {
	{ "create-base-layer",	no_argument,		NULL,	'B'		},
	{ "config",		required_argument,	NULL,	'c'		},
	{ "copy",		required_argument,	NULL,	'C'		},
	{ "exclude",		required_argument,	NULL,	'X'		},
	{ "use-layer",		required_argument,	NULL,	'L'		},
	{ "bindir",		required_argument,	NULL,	OPT_BINDIR	},
	{ "force",		no_argument,		NULL,	'f'		},
	{ "debug",		no_argument,		NULL,	'd'		},
	{ "ignore-change",	required_argument,	NULL,	'I'		},

	{ NULL },
};

static bool
config_set_ignore_changes(struct imgdelta_config *cfg, const char *ignore_string)
{
	char *copy, *s;

	copy = strdup(ignore_string);
	for (s = strtok(copy, ","); s; s = strtok(NULL, ",")) {
		if (!strcmp(s, "mtime")) {
			cfg->ignore_change_mask |= CMP_MTIME_CHANGED;
		} else
		if (!strcmp(s, "owner")) {
			cfg->ignore_change_mask |= CMP_OWNER_CHANGED;
		} else
		if (!strcmp(s, "mode")) {
			cfg->ignore_change_mask |= CMP_MODE_CHANGED;
		} else {
			return false;
		}
	}

	free(copy);
	return true;
}

static void
config_add_entry_symlink(struct imgdelta_config *cfg, const char *entry_point_name, const char *symlink_path)
{
	strutil_mapping_add(&cfg->entry_point_symlinks, entry_point_name, symlink_path);
}

static bool
read_config(struct imgdelta_config *cfg, const char *filename)
{
	char buffer[256];
	int lineno = 0;
	FILE *fp = NULL;
	bool ok = false;

	trace("Reading config file %s", filename);
	if (!(fp = fopen(filename, "r"))) {
		log_error("%s: %m", filename);
		goto done;
	}

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		char *kwd, *value;

		buffer[strcspn(buffer, "\r\n")] = '\0';
		lineno ++;

		if (buffer[0] == '#' || !(kwd = strtok(buffer, " \t")))
			continue;

		if (!(value = strtok(NULL, "")))
			value = "";
		else
			value = __strutil_trim(value);

		if (!strcmp(kwd, "copy") || !strcmp(kwd, "stacked-mount")) {
			if (value[0] != '/') {
				log_error("%s:%u: argument to %s must be an absolute path", filename, lineno, kwd);
				goto done;
			}

			strutil_array_append(&cfg->stacked_mounts, value);
		} else
		if (!strcmp(kwd, "exclude")) {
			if (value[0] != '/') {
				log_error("%s:%u: argument to %s must be an absolute path", filename, lineno, kwd);
				goto done;
			}

			strutil_array_append(&cfg->excldirs, value);
		} else
		if (!strcmp(kwd, "makedir") || !strcmp(kwd, "transparent-mount")) {
			if (value[0] != '/') {
				log_error("%s:%u: argument to %s must be an absolute path", filename, lineno, kwd);
				goto done;
			}

			strutil_array_append(&cfg->transparent_mounts, value);
		} else
		if (!strcmp(kwd, "entry-point")) {
			if (value[0] != '/') {
				log_error("%s:%u: argument to %s must be an absolute path", filename, lineno, kwd);
				goto done;
			}

			strutil_array_append(&cfg->entry_points, value);
		} else
		if (!strcmp(kwd, "install-symlink")) {
			char *entry_point_name, *link_path = NULL;
			char *equals;

			entry_point_name = value;
			if ((equals = strstr(value, "=")) != NULL) {
				*equals++ = '\0';
				link_path = equals;
			}

			config_add_entry_symlink(cfg, entry_point_name, link_path);
		} else
		if (!strcmp(kwd, "ignore-change")) {
			if (!config_set_ignore_changes(cfg, value))
				goto done;
		} else {
			log_error("%s:%u: unknown keyword \"%s\"", filename, lineno, kwd);
			goto done;
		}
	}

	ok = true;

done:
	if (fp)
		fclose(fp);
	return ok;
}

int
main(int argc, char **argv)
{
	struct imgdelta_config config = { 0 };
	char *layer_path;
	int c, rv;

	if (fsutil_exists("/etc/imgdelta.conf") && !read_config(&config, "/etc/imgdelta.conf"))
		return 1;

	while ((c = getopt_long(argc, argv, "BC:L:X:c:df", long_options, NULL)) != EOF) {
		switch (c) {
		case 'B':
			config.create_base_layer = true;
			break;

		case 'c':
			if (!read_config(&config, optarg))
				return 1;
			break;

		case 'C':
			strutil_array_append(&config.stacked_mounts, optarg);
			break;

		case 'L':
			strutil_array_append(&config.layers_used, optarg);
			break;

		case 'I':
			if (!config_set_ignore_changes(&config, optarg)) {
				log_error("Unknown value \"%s\" to --ignore-change option", optarg);
				return 1;
			}
			break;

		case 'X':
			strutil_array_append(&config.excldirs, optarg);
			break;

		case 'd':
			config.debug += 1;
			break;

		case 'f':
			config.force = true;
			break;

		case OPT_BINDIR:
			config.install_bindir = optarg;
			break;

		default:
			log_error("Unknown option\n");
			return 1;
		}
	}

	tracing_set_level(config.debug);
	trace("tracing set to %u", config.debug);

	if (optind + 1 != argc) {
		log_error("Expecting exactly one argument: output-layer");
		return 1;
	}

	layer_path = pathutil_sanitize(argv[optind++]);

	config.layer = wormhole_layer_new(basename(layer_path), layer_path, 0);

	if (config.stacked_mounts.count == 0) {
		const char **dirs = default_copydirs, *path;

		for (dirs = default_copydirs; (path = *dirs++) != NULL; )
			strutil_array_append(&config.stacked_mounts, path);
	}

	if (tracing_level > 0) {
		unsigned int i;

		trace("=== Configuration ===");
		trace("Output layer: %s", config.layer->name);
		trace("Layer path:   %s", config.layer->path);
		trace("Image path:   %s", config.layer->image_path);
		if (config.create_base_layer)
			trace("  (creating base layer)");
		else
			for (i = 0; i < config.layers_used.count; ++i)
				trace("  %s", config.layers_used.data[i]);
		trace("Dirs to copy");
		for (i = 0; i < config.stacked_mounts.count; ++i)
			trace("  %s", config.stacked_mounts.data[i]);
		if (config.excldirs.count)
			trace("Excluded");
		for (i = 0; i < config.excldirs.count; ++i)
			trace("  %s", config.excldirs.data[i]);

		if (config.entry_points.count)
			trace("Entry points");
		for (i = 0; i < config.entry_points.count; ++i)
			trace("  %s", config.entry_points.data[i]);
	}

	if (config.layers_used.count == 0 && !config.create_base_layer) {
		log_error("No lower layers specified (if you want to create a base layer, explicitly usr --create-base-layer)");
		return 1;
	}
	if (config.layers_used.count != 0 && config.create_base_layer) {
		log_error("You want me to create a base layer, but specified lower layers");
		return 1;
	}

	if (fsutil_exists(config.layer->path)) {
		if (!config.force) {
			log_error("layer root \"%s\" already exists, timidly bailing out", config.layer->path);
			return 1;
		}
		if (!fsutil_remove_recursively(config.layer->path))
			return 1;
	}

	/* should check for CAP_CHOWN */
	if (geteuid() == 0)
		can_chown = true;

	if (!fsutil_dir_is_mountpoint("/")) {
		log_warning("Running inside what looks like a chroot environment.");
		config.running_inside_chroot = true;
	}

	/* Traverse the entire filesystem and modify the image accordingly. */
	rv = update_image(&config);

	if (rv == 0)
		rv = write_layer_config(&config);

	if (rv == 0 && config.layer->entry_points.count) {
		trace("=== Creating wrapper scripts ===");

		/* Create wrapper scripts for the utilities mentioned by the
		 * config file.
		 * For the time being, do not create symlinks in /usr/bin yet
		 */
		if (!wormhole_layer_write_wrappers(config.layer, config.install_bindir))
			rv = 1;
	}

	return rv;
}
