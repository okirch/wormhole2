/*
 * util.h
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

#ifndef _WORMHOLE_UTIL_H
#define _WORMHOLE_UTIL_H

#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>

struct strutil_array {
	unsigned int		count;
	char **			data;
};

struct fsutil_tempdir {
	char *		path;
	bool		mounted;
};

extern const char *		pathutil_const_basename(const char *path);
extern const char *		pathutil_dirname(const char *path);
extern char *			pathutil_sanitize(const char *path);
extern void			pathutil_concat2(char **path_p, const char *parent, const char *name);
extern char *			pathutil_expand(const char *orig_path, bool quiet);

struct procutil_command {
	const char *	root_directory;
	const char *	working_directory;
	const char *	procfs_mountpoint;
	char **		argv;
};

extern const char *		procutil_concat_argv(int argc, char **argv);
extern char *			procutil_command_path(const char *argv0);
extern pid_t			procutil_fork_with_socket(int *fdp);
extern void			procutil_install_sigchild_handler(void);
extern pid_t			procutil_get_exited_child(int *status);
extern bool			procutil_wait_for(pid_t pid, int *status);
extern bool			procutil_child_status_okay(int status);
extern bool			procutil_get_exit_status(int status, int *exit_status_p);
extern const char *		procutil_child_status_describe(int status);

enum {
	PROCUTIL_CHILD,
	PROCUTIL_EXITED,
	PROCUTIL_CRASHED
};
extern int			procutil_fork_and_wait(int *exit_status);

extern void			procutil_command_init(struct procutil_command *cmd, char **argv);
extern bool			procutil_command_run(struct procutil_command *cmd, int *status_ret);
extern bool			procutil_command_exec(struct procutil_command *cmd, const char *argv0);

extern bool			wormhole_create_namespace(void);
extern bool			wormhole_create_user_namespace(bool as_root);
extern bool			wormhole_create_init_namespace(void);

extern void			fsutil_tempdir_init(struct fsutil_tempdir *td);
extern char *			fsutil_tempdir_path(struct fsutil_tempdir *td);
extern bool			fsutil_tempdir_mount(struct fsutil_tempdir *td);
extern bool			fsutil_tempdir_unmount(struct fsutil_tempdir *td);
extern bool			__fsutil_tempdir_unmount(struct fsutil_tempdir *td);
extern int			fsutil_tempdir_cleanup(struct fsutil_tempdir *td);
extern int			fsutil_tempfile(const char *basename, char *path, size_t size);

extern bool			fsutil_makedirs(const char *path, int mode);
extern bool			fsutil_makefile(const char *path, int mode);
extern bool			fsutil_create_empty(const char *path);
extern bool			fsutil_check_path_prefix(const char *path, const char *potential_prefix);
extern const char *		fsutil_strip_path_prefix(const char *path, const char *potential_prefix);
extern int			fsutil_get_dtype(const char *path);
extern int			__fsutil_get_dtype(const struct stat *st);
extern const char *		fsutil_dtype_as_string(int);
extern bool			__fsutil_is_whiteout(const struct stat *st);
extern bool			fsutil_isdir(const char *path);
extern bool			fsutil_isblk(const char *path);
extern bool			fsutil_dir_is_empty(const char *path);
extern bool			fsutil_exists(const char *path);
extern bool			fsutil_exists_nofollow(const char *path);
extern bool			fsutil_is_executable(const char *path);
extern bool			fsutil_remove_recursively(const char *dir_path);
extern const char *		fsutil_get_filesystem_type(const char *path);

/* ftw input flags */
#define FSUTIL_FTW_IGNORE_OPEN_ERROR	0x0001
#define FSUTIL_FTW_DEPTH_FIRST		0x0002
#define FSUTIL_FTW_PRE_POST_CALLBACK	0x0004
#define FSUTIL_FTW_ONE_FILESYSTEM	0x0008
#define FSUTIL_FTW_OVERRIDE_OPEN_ERROR	0x0010
#define FSUTIL_FTW_SORTED		0x0020
#define FSUTIL_FTW_NEED_STAT		0x0040

/* ftw callback flags */
#define FSUTIL_FTW_PRE_DESCENT		0x0010
#define FSUTIL_FTW_POST_DESCENT		0x0020

enum {
	FTW_ERROR,
	FTW_ABORT,
	FTW_SKIP,
	FTW_CONTINUE
};

struct fsutil_ftw_cursor {
	const struct dirent *	d;
	char			path[PATH_MAX];
	const char *		relative_path;

	const struct stat *	st;
	struct stat		_st;
};

typedef int			fsutil_ftw_cb_fn_t(const char *dir_path, const struct dirent *d, int flags, void *closure);
extern bool			fsutil_ftw(const char *dir_path, fsutil_ftw_cb_fn_t *callback, void *closure, int flags);

extern struct fsutil_ftw_ctx *	fsutil_ftw_open(const char *dir_path, int flags, const char *root_dir);
extern bool			fsutil_ftw_exclude(struct fsutil_ftw_ctx *ctx, const char *path);
extern const struct dirent *	fsutil_ftw_next(struct fsutil_ftw_ctx *ctx, struct fsutil_ftw_cursor *cursor);
extern bool			fsutil_ftw_skip(struct fsutil_ftw_ctx *ctx, const struct fsutil_ftw_cursor *cursor);
extern void			fsutil_ftw_ctx_free(struct fsutil_ftw_ctx *ctx);

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
extern bool			fsutil_lazy_umount(const char *path);
extern bool			fsutil_make_fs_private(const char *dir, bool maybe_in_chroot);
extern bool			fsutil_same_file(const char *path1, const char *path2);
extern bool			fsutil_dir_is_mountpoint(const char *path);
extern const char *		fsutil_makedir2(const char *parent, const char *name);
extern const char *		fsutil_makefile2(const char *parent, const char *name);
extern bool			fsutil_copy_file(const char *system_path, const char *image_path, const struct stat *st);

enum {
	FSUTIL_MTAB_ITERATOR = 1,
	FSUTIL_FSTAB_ITERATOR,
};

typedef struct fsutil_mount_iterator fsutil_mount_iterator_t;

typedef struct fsutil_mount_cursor {
	const char *		mountpoint;
	const char *		fstype;
	const char *		fsname;
	const char *		options;

	union {
		struct {
			const struct strutil_array *dirs;
		} overlay;
	};
} fsutil_mount_cursor_t;

extern fsutil_mount_iterator_t *fsutil_mount_iterator_create(const char *root_path, int type, const char *mtab);
extern bool			fsutil_mount_iterator_next(fsutil_mount_iterator_t *, fsutil_mount_cursor_t *);
extern void			fsutil_mount_iterator_free(fsutil_mount_iterator_t *);

static inline const char *
__pathutil_concat2(const char *parent, const char *name)
{
        static char path[PATH_MAX];

        if (!strcmp(parent, "/"))
                parent = "";

        while (*name == '/')
                ++name;
        snprintf(path, sizeof(path), "%s/%s", parent, name);
        return path;
}

extern bool			strutil_equal(const char *s1, const char *s2);
extern bool			strutil_string_in_list(const char *needle, const char **haystack);
extern void			strutil_set(char **var, const char *value);
extern char *			__strutil_trim(char *);

static inline void
strutil_drop(char **var)
{
	strutil_set(var, NULL);
}

extern void			strutil_array_init(struct strutil_array *);
extern void			strutil_array_append(struct strutil_array *, const char *);
extern bool			strutil_array_contains(const struct strutil_array *, const char *);
extern void			strutil_array_append_array(struct strutil_array *, const struct strutil_array *);
extern void			strutil_array_sort(struct strutil_array *);
extern void			strutil_array_destroy(struct strutil_array *);
extern char *			strutil_array_join(const struct strutil_array *, const char *sepa);
extern void			strutil_split(const char *string, const char *sepa, struct strutil_array *result);

struct strutil_dynstr {
	char *		_value;
	unsigned int	_len, _size;
};
#define STRUTIL_DYNSTR_INIT	{ NULL, 0, 0 }

extern void			strutil_dynstr_init(struct strutil_dynstr *);
extern void			strutil_dynstr_destroy(struct strutil_dynstr *);
extern void			strutil_dynstr_putc(struct strutil_dynstr *, char);
extern void			strutil_dynstr_append(struct strutil_dynstr *, const char *);
extern void			strutil_dynstr_appendf(struct strutil_dynstr *, const char *fmt, ...);
extern const char *		strutil_dynstr_value(const struct strutil_dynstr *);

struct pathutil_parser {
	const char *	relative_path;
	const char *	pos;

	char		namebuf[NAME_MAX];
	char		pathbuf[PATH_MAX];
};

extern void			pathutil_parser_init(struct pathutil_parser *parser, const char *path);
extern bool			pathutil_parser_next(struct pathutil_parser *parser);

enum {
	FSUTIL_MISMATCH_TYPE = -2,
	FSUTIL_MISMATCH_MISSING = -1,
	FSUTIL_FILE_IDENTICAL = 0,

	/* The rest are bits that can be tested for */
	FSUTIL_FILE_SMALLER	= 0x001,
	FSUTIL_FILE_BIGGER	= 0x002,
	FSUTIL_FILE_YOUNGER	= 0x004,
	FSUTIL_FILE_OLDER	= 0x008,
};

extern int			fsutil_inode_compare(const char *path1, const char *path2);
extern bool			fsutil_file_content_identical(const char *path1, const char *path2);

typedef struct strutil_mapping {
	unsigned int		count;
	struct strutil_mapping_pair {
		char *		key;
		char *		value;
	} *data;
} strutil_mapping_t;

extern void			strutil_mapping_init(strutil_mapping_t *);
extern void			strutil_mapping_destroy(strutil_mapping_t *);
extern void			strutil_mapping_add(strutil_mapping_t *, const char *key, const char *value);
extern void			strutil_mapping_add_no_override(strutil_mapping_t *, const char *key, const char *value);

#endif // _WORMHOLE_UTIL_H
