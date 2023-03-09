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

static bool		can_chown = false;
static const char *	default_copydirs[] = {
	"/bin",
	"/sbin",
	"/lib",
	"/lib64",
	"/usr",
	NULL,
};

bool
__mount_bind(const char *src, const char *dst, int extra_flags)
{
	trace("Binding %s to %s\n", src, dst);
	if (mount(src, dst, NULL, MS_BIND | extra_flags, NULL) < 0) {
		log_error("Unable to bind mount %s on %s: %m\n", src, dst);
		return false;
	}
	return true;
}

static const struct stat *
do_stat(const char *path, struct stat *stb)
{
	if (lstat(path, stb) < 0) {
		log_error("%s: cannot stat: %m", path);
		return NULL;
	}

	return stb;
}

static int
__stat_to_type(const struct stat *st)
{
	switch (st->st_mode & S_IFMT) {
	case S_IFREG:
		return DT_REG;
	case S_IFDIR:
		return DT_DIR;
	case S_IFLNK:
		return DT_LNK;
	case S_IFCHR:
		return DT_CHR;
	case S_IFBLK:
		return DT_BLK;
	case S_IFSOCK:
		return DT_SOCK;
	case S_IFIFO:
		return DT_FIFO;
	default:
		break;
	}
	return DT_UNKNOWN;
}

static inline bool
__attrs_changed(const char *path, const struct stat *sta, const struct stat *stb)
{
	bool changed = false;

	if (sta->st_mode != stb->st_mode) {
		trace("%s: mode changed 0%o -> 0%o", path, sta->st_mode, stb->st_mode);
		changed = true;
	}

	if (!S_ISDIR(stb->st_mode)) {
		if (sta->st_size != stb->st_size) {
			trace("%s: size changed %lu -> %lu", path, (long) sta->st_size, (long) stb->st_size);
			changed = true;
		}

		if (sta->st_mtim.tv_sec != stb->st_mtim.tv_sec
		 || sta->st_mtim.tv_nsec / 1000 != stb->st_mtim.tv_nsec / 1000) {
			trace("%s: mtime changed %lu.%09lu -> %lu.%09lu", path,
					(long) sta->st_mtim.tv_sec,
					(long) sta->st_mtim.tv_nsec,
					(long) stb->st_mtim.tv_sec,
					(long) stb->st_mtim.tv_nsec);
			changed = true;
		}
	}

	if (can_chown
	 && sta->st_uid != stb->st_uid
	 && sta->st_gid != stb->st_gid) {
		trace("%s: owner changed from %u:%u -> %u:%u", path,
				(int) sta->st_uid,
				(int) sta->st_gid,
				(int) stb->st_uid,
				(int) stb->st_gid);
		changed = true;
	}

	return changed;
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
copy_file(const char *system_path, const char *image_path, const struct stat *st)
{
	char buffer[65536];
	unsigned long copied = 0;
	int srcfd = -1, dstfd = -1;
	int rcount;
	bool ok = false;

	srcfd = open(system_path, O_RDONLY);
	if (srcfd < 0) {
		log_error("%s: unable to open file: %m", system_path);
		return false;
	}

	unlink(image_path);

	dstfd = open(image_path, O_CREAT | O_WRONLY | O_TRUNC, st->st_mode & 0777);
	if (dstfd < 0) {
		log_error("%s: unable to create file: %m", image_path);
		close(srcfd);
		return false;
	}

	while ((rcount = read(srcfd, buffer, sizeof(buffer))) > 0) {
		int written = 0, wcount;

		while (written < rcount) {
			wcount = write(dstfd, buffer + written, rcount - written);
			if (wcount < 0) {
				log_error("%s: write error: %m", image_path);
				goto failed;
			}

			written += wcount;
		}

		copied += rcount;
	}

	trace("%s: copied %lu bytes", image_path, copied);
	ok = true;

failed:
	if (srcfd >= 0)
		close(srcfd);
	if (dstfd >= 0)
		close(dstfd);
	return ok;
}

static bool
__image_copy(const char *image_root, const char *src_path, const char *relative_src_path, int dt_type, const struct stat *st)
{
	const char *image_path;
	struct stat _stb;

	trace("copy %s -> %s%s", src_path, image_root, relative_src_path);
	if (st == NULL && !(st = do_stat(src_path, &_stb)))
		return false;

	image_path = __fsutil_concat2(image_root, relative_src_path);
	if (dt_type == DT_DIR) {
		trace2("create dir %s", image_path);
		if (!fsutil_makedirs(image_path, st->st_mode)) {
			log_error("%s: cannot create directory: %m", image_path);
			return false;
		}
	} else
	if (dt_type == DT_REG) {
		trace2("copy regular file %s", image_path);
		if (!copy_file(src_path, image_path, st))
			return false;
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
			log_error("%s: unable to create symlink to: %m", src_path, target);
			return false;
		}
	} else {
		log_error("dirent type %u not yet implemented", dt_type);
		return false;
	}

	return __image_update_attrs(image_path, st);
}

static bool
image_copy(const char *image_root, struct fsutil_ftw_cursor *cursor, const struct stat *st)
{
	assert(cursor);
	return __image_copy(image_root, cursor->path, cursor->relative_path, cursor->d->d_type, st);
}

static bool
image_compare_copy(const char *image_root, struct fsutil_ftw_cursor *cursor)
{
	const char *image_path;
	struct stat system_stb, image_stb;

	if (!do_stat(cursor->path, &system_stb))
		return false;

	image_path = __fsutil_concat2(image_root, cursor->path);
	if (do_stat(image_path, &image_stb)
	 && !__attrs_changed(cursor->path, &system_stb, &image_stb)) {
		trace3("%s: unchanged", cursor->path);
		return true;
	}

	trace("%s: needs an update", cursor->path);
	return image_copy(image_root, cursor, &system_stb);
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

        ctx = fsutil_ftw_open("/", 0, src_path);
	if (mkdir(dst_path, 0755) < 0 && errno != EEXIST) {
		log_error("%s: cannot create directory: %m", dst_path);
		return false;
	}

        while (fsutil_ftw_next(ctx, &cursor)) {
		char dst[PATH_MAX];

		snprintf(dst, sizeof(dst), "%s/%s", dst_path, cursor.relative_path);
		ok = image_copy(dst_path, &cursor, NULL) && ok;
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

		dt_type = __stat_to_type(&stb);
		if (!__image_copy(image_root, dir_path, dir_path, dt_type, &stb))
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
			ok = image_compare_copy(image_root, &system_cursor) && ok;
			system_cursor.d = NULL;
			image_cursor.d = NULL;
		} else
		if (r < 0) {
			trace("%s: added to system", system_cursor.path);
			ok = image_copy(image_root, &system_cursor, NULL) && ok;
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
		ok = image_copy(image_root, &system_cursor, NULL) && ok;
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

		for (i = 0; i < cfg->layers_used.count; ++i) {
			const char *layer_name = cfg->layers_used.data[i];

			if (!wormhole_layers_resolve(&resolved, layer_name))
				return 1;
		}

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
	for (i = 0; i < cfg->copydirs.count; ++i) {
		const char *dir_path = cfg->copydirs.data[i];

		rv = update_image_partial(cfg, overlay, dir_path);
		if (rv != 0)
			return rv;
	}

	if (cfg->makedirs.count) {
		trace("=== Creating empty directories ===");

		for (i = 0; i < cfg->makedirs.count; ++i) {
			const char *dir_path = cfg->makedirs.data[i];

			if (!fsutil_makedirs(__fsutil_concat2(overlay, dir_path), 0755))
				rv = 1;
		}

		if (rv)
			return rv;
	}

	trace("=== Recursively copying image delta to %s ===", cfg->layer->image_path);
	if (!copy_recursively(upperdir, cfg->layer->image_path))
		return 1;

	return 0;
}

static int
update_image(struct imgdelta_config *cfg)
{
	struct fsutil_tempdir tempdir;
	int rv;

	fsutil_tempdir_init(&tempdir);

	trace("=== Initialiting namespace ===");
	if (geteuid() == 0) {
		if (!wormhole_create_namespace())
			return 1;
	} else {
		if (!wormhole_create_user_namespace(true))
			return 1;
	}

        if (!fsutil_make_fs_private("/", false))
                return 1;

	if (!fsutil_tempdir_mount(&tempdir))
		return 1;

	rv = update_image_work(cfg, fsutil_tempdir_path(&tempdir));

	fsutil_tempdir_cleanup(&tempdir);
	return rv;
}

static bool
__update_layer_config(struct wormhole_layer *layer, struct imgdelta_config *cfg)
{
	struct strutil_array work = { 0 };
	unsigned int i;

	layer->is_root = cfg->create_base_layer;

	strutil_array_append_array(&work, &cfg->copydirs);
	strutil_array_append_array(&work, &cfg->makedirs);
	strutil_array_sort(&work);

	for (i = 0; i < work.count; ++i) {
		const char *dir_path = work.data[i];
		unsigned int len;

		strutil_array_append(&layer->directories, dir_path);

		len = strlen(dir_path);
		while (i + 1 < work.count) {
			const char *next_dir = work.data[i + 1];

			if (strncmp(dir_path, next_dir, len) || next_dir[len] != '/')
				break;

			/* Skip over the next entry as it is below the one we just copied */
			i += 1;
		}
	}

	if (!cfg->create_base_layer)
		strutil_array_append_array(&layer->used, &cfg->layers_used);

	strutil_array_destroy(&work);
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

static struct option	long_options[] = {
	{ "create-base-layer",
			no_argument,		NULL,	'B'		},
	{ "config",	required_argument,	NULL,	'c'		},
	{ "copy",	required_argument,	NULL,	'C'		},
	{ "exclude",	required_argument,	NULL,	'X'		},
	{ "use-layer",	required_argument,	NULL,	'L'		},
	{ "force",	no_argument,		NULL,	'f'		},
	{ "debug",	no_argument,		NULL,	'd'		},

	{ NULL },
};

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

		if (!strcmp(kwd, "copy")) {
			if (value[0] != '/') {
				log_error("%s:%u: argument to copy must be an absolute path", filename, lineno);
				goto done;
			}

			strutil_array_append(&cfg->copydirs, value);
		} else
		if (!strcmp(kwd, "exclude")) {
			if (value[0] != '/') {
				log_error("%s:%u: argument to exclude must be an absolute path", filename, lineno);
				goto done;
			}

			strutil_array_append(&cfg->excldirs, value);
		} else
		if (!strcmp(kwd, "makedir")) {
			if (value[0] != '/') {
				log_error("%s:%u: argument to makedir must be an absolute path", filename, lineno);
				goto done;
			}

			strutil_array_append(&cfg->makedirs, value);
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
			strutil_array_append(&config.copydirs, optarg);
			break;

		case 'L':
			strutil_array_append(&config.layers_used, optarg);
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

	if (config.copydirs.count == 0) {
		const char **dirs = default_copydirs, *path;

		for (dirs = default_copydirs; (path = *dirs++) != NULL; )
			strutil_array_append(&config.copydirs, path);
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
		for (i = 0; i < config.copydirs.count; ++i)
			trace("  %s", config.copydirs.data[i]);
		if (config.excldirs.count)
			trace("Excluded");
		for (i = 0; i < config.excldirs.count; ++i)
			trace("  %s", config.excldirs.data[i]);
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

	/* Traverse the entire filesystem and modify the image accordingly. */
	rv = update_image(&config);

	if (rv == 0)
		rv = write_layer_config(&config);

	return rv;
}
