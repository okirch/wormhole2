/*
 * utility functions for wormhole
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

#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <dirent.h>
#include <sched.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <fcntl.h>
#include <libgen.h>
#include <errno.h>
#include <assert.h>

#include "tracing.h"
#include "util.h"


const char *
procutil_concat_argv(int argc, char **argv)
{
	static char buffer[8192];
	unsigned int pos, n;
	int i;

	if (argc < 0) {
		for (argc = 0; argv[argc]; ++argc)
			;
	}

	pos = 0;
	for (i = 0; i < argc; ++i) {
		const char *s = argv[i];

		n = strlen(s);

		/* We need to be able to include 3 additional chars (space, and 2x") plus
		 * the ellipsis string " ..."
		 */
		if (pos + n >= sizeof(buffer) - 20) {
			strcpy(buffer + pos, " ...");
			break;
		}

		if (i)
			buffer[pos++] = ' ';
		if (strchr(s, ' ') == NULL) {
			strcpy(buffer + pos, s);
			pos += n;
		} else {
			buffer[pos++] = '"';
			strcpy(buffer + pos, s);
			pos += n;
			buffer[pos++] = '"';
		}
	}

	return buffer;
}

const char *
pathutil_const_basename(const char *path)
{
	const char *s;

	if (path == NULL)
		return NULL;

	s = strrchr(path, '/');
	if (s == NULL)
		return path;

	/* Path ends with a slash */
	if (s[1] == '\0')
		return NULL;

	return &s[1];
}

const char *
pathutil_dirname(const char *path)
{
	static char buffer[PATH_MAX];

	strncpy(buffer, path, sizeof(buffer));
	return dirname(buffer);
}

bool
strutil_string_in_list(const char *needle, const char **haystack)
{
	const char *straw;

	while ((straw = *haystack++) != NULL) {
		if (!strcmp(needle, straw))
			return true;
	}
	return false;
}


static const char *
wormhole_find_command(const char *argv0)
{
	static char cmdbuf[PATH_MAX];
	const char *path_env;
	char path[PATH_MAX], *s, *next;

	if ((path_env = getenv("PATH")) != NULL) {
		if (strlen(path_env) > sizeof(path))
			log_fatal("cannot resolve command - PATH too long");
		strncpy(path, path_env, sizeof(path));
	} else {
		if (confstr(_CS_PATH, path, sizeof(path)) >= sizeof(path))
			log_fatal("cannot resolve command - PATH confstr too long");
	}

	for (s = path; s != NULL; s = next) {
		if ((next = strchr(s, ':')) != NULL)
			*next++ = '\0';

		if (*s != '\0') {
			snprintf(cmdbuf, sizeof(cmdbuf), "%s/%s", s, argv0);
			if (access(cmdbuf, X_OK) == 0)
				return cmdbuf;
		} else {
			/* empty PATH component indicates CWD */
			if (access(argv0, X_OK) == 0)
				return argv0;
		}
	}

	return argv0;
}

char *
procutil_command_path(const char *argv0)
{
	if (strchr(argv0, '/') == NULL)
		argv0 = wormhole_find_command(argv0);

	return strdup(argv0);
}

pid_t
procutil_fork_with_socket(int *fdp)
{
	int fdpair[2];
	pid_t pid;

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, fdpair) < 0) {
		log_error("%s: socketpair failed: %m", __func__);
		return -1;
	}

	if ((pid = fork()) < 0) {
		log_error("%s: fork failed: %m", __func__);
		close(fdpair[0]);
		close(fdpair[1]);
		return -1;
	}

	if (pid > 0) {
		*fdp = fdpair[0];
		close(fdpair[1]);
	} else {
		close(fdpair[0]);
		*fdp = fdpair[1];
	}

	return pid;
}

void
procutil_command_init(struct procutil_command *cmd, char **argv)
{
	memset(cmd, 0, sizeof(*cmd));
	cmd->argv = argv;
}

bool
procutil_command_exec(struct procutil_command *cmd, const char *command)
{
	if (cmd->root_directory) {
		if (chroot(cmd->root_directory) < 0) {
			log_error("Unable to chroot to %s: %m", cmd->root_directory);
			exit(67);
		}

		if (chdir("/") < 0) {
			log_error("Unable to chdir to new root: %m");
			exit(68);
		}
	}

	if (cmd->working_directory) {
		if (chdir(cmd->working_directory) < 0) {
			log_error("Unable to chdir to %s: %m", cmd->working_directory);
			exit(69);
		}
	}

	trace("Executing \"%s\"", procutil_concat_argv(-1, cmd->argv));
	execvp(command, cmd->argv);

	log_error("Unable to execute %s: %m", command);
	exit(66);
}

bool
procutil_command_run(struct procutil_command *cmd, int *status_ret)
{
	int status;
	pid_t pid;

	if ((pid = fork()) < 0) {
		log_error("%s: fork failed: %m", __func__);
		return false;
	}

	if (pid == 0) {
		(void) procutil_command_exec(cmd, cmd->argv[0]);
	}

	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR) {
			log_error("%s: wait failed: %m", __func__);
			return false;
		}
	}

	if (status_ret)
		*status_ret = status;

	return true;
}

static bool
write_single_line(const char *filename, const char *buf)
{
	FILE *fp;

	trace("Writing to %s: %s\n", filename, buf);
	if ((fp = fopen(filename, "w")) == NULL) {
		log_error("Unable to open %s: %m", filename);
		return false;
	}

	fputs(buf, fp);
	if (fclose(fp) == EOF) {
		log_error("Error writing to %s: %m", filename);
		return false;
	}

	return true;
}


/*
 * Create namespace
 */
bool
wormhole_create_namespace(void)
{
	struct stat stb1, stb2;

	if (stat("/proc/self/ns/mnt", &stb1) < 0) {
		log_error("stat(\"/proc/self/ns/mnt\") failed: %m");
		return false;
	}

	if (unshare(CLONE_NEWNS) < 0) {
		log_error("unshare(CLONE_NEWNS) failed: %m");
		return false;
	}

	if (stat("/proc/self/ns/mnt", &stb2) < 0) {
		log_error("stat(\"/proc/self/ns/mnt\") failed: %m");
		return false;
	}
	if (stb1.st_dev == stb2.st_dev && stb1.st_ino == stb2.st_ino) {
		log_error("Something is not quite right");
		return false;
	}

	return true;
}

static bool
write_setgroups(const char *verb)
{
	return write_single_line("/proc/self/setgroups", "deny");
}

static int
write_uid_map(uid_t orig_uid, uid_t container_uid)
{
	char buffer[256];

	snprintf(buffer, sizeof(buffer), "%d %d 1", container_uid, orig_uid);
	return write_single_line("/proc/self/uid_map", buffer);
}

static int
write_gid_map(gid_t orig_gid, gid_t container_gid)
{
	char buffer[256];

	snprintf(buffer, sizeof(buffer), "%d %d 1", container_gid, orig_gid);
	return write_single_line("/proc/self/gid_map", buffer);
}

bool
wormhole_create_user_namespace(bool as_root)
{
	uid_t orig_uid;
	gid_t orig_gid;

	orig_uid = getuid();
	orig_gid = getgid();

	if (unshare(CLONE_NEWUSER|CLONE_NEWNS) < 0) {
		log_error("unshare() failed: %m");
		return false;
	}

	if (!write_uid_map(orig_uid, as_root? 0 : orig_uid))
		return false;

	if (!write_setgroups("deny"))
		return false;

	if (!write_gid_map(orig_gid, as_root? 0 : orig_gid))
		return false;

	return true;
}

/*
 * Reap exited children
 */
static bool	have_waiting_children = false;

static void
reaper(int sig)
{
	have_waiting_children = true;
}

void
procutil_install_sigchild_handler(void)
{
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	act.sa_handler = reaper;
	sigaction(SIGCHLD, &act, NULL);
}

pid_t
procutil_get_exited_child(int *status)
{
	pid_t pid;

	if (!have_waiting_children)
		return -1;

	have_waiting_children = false;
	pid = waitpid(-1, status, WNOHANG);

	if (pid < 0 && errno != ECHILD)
		return pid;

	have_waiting_children = true;
	return pid;
}

bool
procutil_wait_for(pid_t pid, int *status)
{
	while (waitpid(pid, status, 0) < 0) {
		if (errno != EINTR) {
			log_error("%s: wait failed: %m", __func__);
			return false;
		}
	}

	return true;
}

bool
procutil_child_status_okay(int status)
{
	if (WIFSIGNALED(status))
		return false;

	if (!WIFEXITED(status))
		return false;

	return WEXITSTATUS(status) == 0;
}

bool
procutil_get_exit_status(int status, int *exit_status_p)
{
	if (WIFEXITED(status)) {
		*exit_status_p = WEXITSTATUS(status);
		return true;
	}

	return false;
}

const char *
procutil_child_status_describe(int status)
{
	static char msgbuf[128];

	if (WIFSIGNALED(status)) {
		snprintf(msgbuf, sizeof(msgbuf), "crashed with signal %d", WTERMSIG(status));
	} else if (WIFEXITED(status)) {
		snprintf(msgbuf, sizeof(msgbuf), "exited with status %d", WEXITSTATUS(status));
	} else {
		snprintf(msgbuf, sizeof(msgbuf), "weird status word 0x%x", status);
	}
	return msgbuf;
}

void
fsutil_tempdir_init(struct fsutil_tempdir *td)
{
	char dirtemplate[PATH_MAX];
	char *tempdir;

	memset(td, 0, sizeof(*td));

	if ((tempdir = getenv("TMPDIR")) == NULL)
		tempdir = "/tmp";
	snprintf(dirtemplate, sizeof(dirtemplate), "%s/mounts.XXXXXX", tempdir);

	tempdir = mkdtemp(dirtemplate);
	if (tempdir == NULL)
		log_fatal("Unable to create tempdir: %m\n");

	td->path = strdup(tempdir);
}

char *
fsutil_tempdir_path(struct fsutil_tempdir *td)
{
	return td->path;
}

bool
fsutil_tempdir_mount(struct fsutil_tempdir *td)
{
	if (!td->mounted) {
		if (!fsutil_mount_tmpfs(td->path)) {
			log_error("Unable to mount tmpfs in container: %m\n");
			return false;
		}

		td->mounted = true;
	}

	return true;
}

bool
fsutil_tempdir_unmount(struct fsutil_tempdir *td)
{
	if (td->mounted && umount2(td->path, MNT_DETACH) < 0) {
                log_error("Unable to unmount %s: %m", td->path);
		return false;
        }
	td->mounted = false;
	return true;
}

int
fsutil_tempdir_cleanup(struct fsutil_tempdir *td)
{
	if (td->path == NULL)
		return 0;

	if (!fsutil_tempdir_unmount(td))
		return -1;

	/* Child process may have mounted something but failed to detach root.
	 * This can happen if we run in a chroot env, like osc local build */
        if (rmdir(td->path) < 0 && errno == EBUSY) {
		trace("%s is still busy, trying to unmounted", td->path);
		(void) umount2(td->path, MNT_DETACH);

		if (rmdir(td->path) < 0) {
			log_error("Unable to remove temporary mountpoint %s: %m", td->path);
			sleep(1);
			if (rmdir(td->path) == 0)
				return 0;
			log_error("Still unable to remove: %m");
			return -1;
		}
	}

	strutil_drop(&td->path);
	memset(td, 0, sizeof(*td));
	return 0;
}

int
fsutil_tempfile(const char *basename, char *path, size_t size)
{
	char template[PATH_MAX];
	const char *tempdir;
	int fd;

	if ((tempdir = getenv("TMPDIR")) == NULL)
		tempdir = "/tmp";
	snprintf(template, sizeof(template), "%s/%s.XXXXXX", tempdir, basename);

	if ((fd = mkstemp(template)) < 0) {
		log_error("Unable to create temporary file %s.* in %s", basename, tempdir);
		return -1;
	}

	if (strlen(template) + 1 > size) {
		log_error("%s: return buffer too small", __func__);
		unlink(template);
		close(fd);
		return -1;
	}

	strncpy(path, template, size);
	return fd;
}

static int
__fsutil_create_thing(char *path, int mode, int (*creatfn)(const char *path, mode_t mode))
{
	char *slash;
	int ret;

	/* trace("%s(%s)", __func__, path); */
	if (mkdir(path, mode) == 0)
		return 0;

	if (errno == EEXIST)
		return 0;

	slash = strrchr(path, '/');
	while (slash > path && slash[-1] == '/')
		--slash;
	slash[0] = '\0';

	if (*path)
		ret = __fsutil_create_thing(path, mode, mkdir);
	else
		ret = 0;

	slash[0] = '/';
	if (ret >= 0)
		ret = creatfn(path, mode);

	return ret;
}

static bool
fsutil_make_thing(const char *path, int mode, int (*createfn)(const char *path, mode_t mode))
{
	char path_copy[PATH_MAX];

	if (createfn(path, mode) == 0 || errno == EEXIST)
		return true;

	if (errno != ENOENT)
		return false;

	if (strlen(path) + 1 > sizeof(path_copy)) {
		errno = ENAMETOOLONG;
		return false;
	}

	strcpy(path_copy, path);
	if (__fsutil_create_thing(path_copy, mode, createfn) < 0)
		return false;

	return true;
}

bool
fsutil_makedirs(const char *path, int mode)
{
	return fsutil_make_thing(path, mode, mkdir);
}

static int
__create_empty_file(const char *path, mode_t mode)
{
	int fd;

	if ((fd = open(path, O_RDWR|O_CREAT, mode)) < 0)
		return -1;

	close(fd);
	return 0;
}

bool
fsutil_makefile(const char *path, int mode)
{
	return fsutil_make_thing(path, mode, __create_empty_file);
}

bool
fsutil_isdir(const char *path)
{
	struct stat stb;

	if (lstat(path, &stb) < 0)
		return false;

	return !!S_ISDIR(stb.st_mode);
}

bool
fsutil_exists(const char *path)
{
	return access(path, F_OK) >= 0;
}

bool
fsutil_exists_nofollow(const char *path)
{
	struct stat stb;

	if (lstat(path, &stb) >= 0)
		return true;
	return false;
}

bool
fsutil_is_executable(const char *path)
{
	struct stat stb;

	if (stat(path, &stb) < 0)
		return false;

	if (!S_ISREG(stb.st_mode))
		return false;

	if (!(stb.st_mode & S_IXUSR))
		return false;

	return true;
}

bool
fsutil_dir_is_empty(const char *path)
{
	bool empty = true;
	DIR *dir;
	struct dirent *de;

	if ((dir = opendir(path)) == NULL)
		return false;

	while ((de = readdir(dir)) != NULL) {
		if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..")) {
			empty = false;
			break;
		}
	}

	closedir(dir);
	return empty;
}

typedef int	__fsutil_ftw_internal_cb_fn_t(const char *dir_path, int dir_fd, const struct dirent *d, int flags, void *closure);

static bool
__fsutil_ftw(const char *dir_path, int dirfd, struct stat *dir_stat, __fsutil_ftw_internal_cb_fn_t *callback, void *closure, int flags)
{
	DIR *dir;
	struct dirent *d;
	bool cb_pre = false, cb_post = false;
	bool ok = true;

	/* trace3("%s(%s)", __func__, dir_path); */

	dir = fdopendir(dup(dirfd));
	if (dir == NULL) {
		log_error("cannot dup directory fd: %m");
		close(dirfd);
		return false;
	}

	if (flags & FSUTIL_FTW_DEPTH_FIRST)
		cb_post = true;
	else if (flags & FSUTIL_FTW_PRE_POST_CALLBACK)
		cb_pre = cb_post = true;
	else
		cb_pre = true;

	// __make_path_push();
	while (ok && (d = readdir(dir)) != NULL) {
		int cbflags = 0;

		if (d->d_name[0] == '.' && (d->d_name[1] == '\0' || d->d_name[1] == '.'))
			continue;

		if (d->d_type == DT_DIR) {
			struct stat child_stb, *child_stat = NULL;
			char child_path[PATH_MAX];
			int childfd, rv;

			if (flags & FSUTIL_FTW_ONE_FILESYSTEM) {
				if (fstatat(dirfd, d->d_name, &child_stb, AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW) < 0) {
					log_error("can't stat %s/%s: %m", dir_path, d->d_name);
					ok = false;
					continue;
				}

				if (child_stb.st_dev != dir_stat->st_dev) {
					trace("Skipping %s/%s: different filesystem", dir_path, d->d_name);
					continue;
				}

				child_stat = &child_stb;
			}

			childfd = openat(dirfd, d->d_name, O_RDONLY|O_NOCTTY|O_NONBLOCK|O_NOFOLLOW|O_DIRECTORY);
			if (childfd < 0 && errno == EACCES && (flags & FSUTIL_FTW_OVERRIDE_OPEN_ERROR)) {
				(void) fchmodat(dirfd, d->d_name, 0700, 0);
				childfd = openat(dirfd, d->d_name, O_RDONLY|O_NOCTTY|O_NONBLOCK|O_NOFOLLOW|O_DIRECTORY);
			}
			if (childfd < 0) {
				if (!(flags & FSUTIL_FTW_IGNORE_OPEN_ERROR)) {
					log_error("can't open %s/%s: %m", dir_path, d->d_name);
					ok = false;
				}
				continue;
			}

			snprintf(child_path, sizeof(child_path), "%s/%s", dir_path, d->d_name);

			if (cb_pre) {
				rv = callback(dir_path, dirfd, d, cbflags | FSUTIL_FTW_PRE_DESCENT, closure);
				if (rv == FTW_ERROR || rv == FTW_ABORT)
					ok = false;

				if (rv != FTW_CONTINUE)
					continue;
			}

			/* Descend into the directory */
			if (ok)
				ok = __fsutil_ftw(child_path, childfd, child_stat, callback, closure, flags);

			if (cb_post) {
				rv = callback(dir_path, dirfd, d, cbflags | FSUTIL_FTW_POST_DESCENT, closure);
				if (rv == FTW_ERROR || rv == FTW_ABORT)
					ok = false;

				/* In a depth-first traversal, it does not make any sense for the callback
				 * function to return FTW_SKIP as we've already processed the subdir. */
			}

			close(childfd);
		} else {
			int rv;

			rv = callback(dir_path, dirfd, d, cbflags, closure);
			if (rv == FTW_ERROR || rv == FTW_ABORT)
				ok = false;
		}
	}
	// __make_path_pop();

	closedir(dir);
	return ok;
}

struct fsutil_ftw_user_context {
	fsutil_ftw_cb_fn_t *	user_callback;
	void *			user_closure;
};

static int
__fsutil_ftw_callback(const char *dir_path, int dir_fd, const struct dirent *d, int flags, void *closure)
{
	struct fsutil_ftw_user_context *ctx = closure;

	return ctx->user_callback(dir_path, d, flags, ctx->user_closure);
}

bool
fsutil_ftw(const char *dir_path, fsutil_ftw_cb_fn_t *callback, void *closure, int flags)
{
	struct fsutil_ftw_user_context ctx;
	struct stat stb, *dir_stat = NULL;
	int dirfd;
	bool ok = true;

	trace2("%s(%s)", __func__, dir_path);

	dirfd = open(dir_path, O_RDONLY|O_NOCTTY|O_NONBLOCK|O_NOFOLLOW|O_DIRECTORY);
	if (dirfd < 0) {
		if (flags & FSUTIL_FTW_IGNORE_OPEN_ERROR)
			return true;

		log_error("unable to open dir %s: %m", dir_path);
		return false;
	}

	if (flags & FSUTIL_FTW_ONE_FILESYSTEM) {
		if (fstat(dirfd, &stb) < 0) {
			log_error("unable to stat %s: %m", dir_path);
			ok = false;
			goto out;
		}
		dir_stat = &stb;
	}

	ctx.user_callback = callback;
	ctx.user_closure = closure;

	ok = __fsutil_ftw(dir_path, dirfd, dir_stat, __fsutil_ftw_callback, &ctx, flags);

out:
	close(dirfd);
	return ok;
}

/*
 * Recursively remove directory hierarchy
 */
static int
__fsutil_remove_callback(const char *dir_path, int dir_fd, const struct dirent *d, int cbflags, void *dummy_closure)
{
	int flags = 0;

	if (d->d_type == DT_DIR)
		flags = AT_REMOVEDIR;

	if (unlinkat(dir_fd, d->d_name, flags) < 0) {
		log_error("Cannot remove %s/%s: %m", dir_path, d->d_name);
		return FTW_ERROR;
	}

	return FTW_CONTINUE;
}

bool
fsutil_remove_recursively(const char *dir_path)
{
	struct stat stb;
	int dirfd;
	bool ok = true;

	trace2("%s(%s)", __func__, dir_path);

	if (stat(dir_path, &stb) < 0) {
		if (errno == ENOENT)
			return true;
		log_error("%s: cannot stat %s: %m", __func__, dir_path);
		return false;
	}

	if (!S_ISDIR(stb.st_mode)) {
		if (unlink(dir_path) < 0) {
			log_error("Cannot remove %s: %m", dir_path);
			return false;
		}

		return true;
	}

	dirfd = open(dir_path, O_RDONLY|O_NOCTTY|O_NONBLOCK|O_NOFOLLOW|O_DIRECTORY);
	if (dirfd < 0) {
		log_error("unable to open dir %s: %m", dir_path);
		return false;
	}

	ok = __fsutil_ftw(dir_path, dirfd, &stb, __fsutil_remove_callback, NULL,
			FSUTIL_FTW_ONE_FILESYSTEM | FSUTIL_FTW_DEPTH_FIRST | FSUTIL_FTW_OVERRIDE_OPEN_ERROR);

	close(dirfd);

	if (ok && rmdir(dir_path) < 0) {
		log_error("Cannot remove %s: %m", dir_path);
		ok = false;
	}

	return ok;
}

bool
fsutil_create_empty(const char *path)
{
	int fd;

	if ((fd = open(path, O_WRONLY|O_CREAT, 0644)) < 0)
		return false;
	close(fd);
	return true;
}

const char *
fsutil_strip_path_prefix(const char *path, const char *potential_prefix)
{
	unsigned int len;

	if (potential_prefix == NULL || path == NULL)
		return NULL;

	len = strlen(potential_prefix);
	if (strncmp(path, potential_prefix, len) != 0)
		return NULL;

	if (path[len] != '\0' && path[len] != '/')
		return NULL;

	return path + len;
}

bool
fsutil_check_path_prefix(const char *path, const char *potential_prefix)
{
	return fsutil_strip_path_prefix(path, potential_prefix) != NULL;
}

bool
fsutil_same_file(const char *path1, const char *path2)
{
	struct stat stb1, stb2;

	if (stat(path1, &stb1) < 0)
		return false;
	if (stat(path2, &stb2) < 0)
		return false;

	return stb1.st_dev == stb2.st_dev
	    && stb1.st_ino == stb2.st_ino;
}

/*
 * Rather special kind of file comparison
 */
int
fsutil_inode_compare(const char *path1, const char *path2)
{
	struct stat stb1, stb2;
	int verdict = FSUTIL_FILE_IDENTICAL;

	if (lstat(path1, &stb1) < 0)
		return FSUTIL_MISMATCH_MISSING;
	if (lstat(path2, &stb2) < 0)
		return FSUTIL_MISMATCH_MISSING;


	if ((stb1.st_mode & S_IFMT) != (stb2.st_mode & S_IFMT))
		return FSUTIL_MISMATCH_TYPE;

	if (S_ISREG(stb1.st_mode)) {
		if (stb1.st_size < stb2.st_size)
			verdict |= FSUTIL_FILE_SMALLER;
		else if (stb1.st_size > stb2.st_size)
			verdict |= FSUTIL_FILE_BIGGER;
	}

	if (stb1.st_mtime < stb2.st_mtime)
		verdict |= FSUTIL_FILE_YOUNGER;
	else if (stb1.st_mtime > stb2.st_mtime)
		verdict |= FSUTIL_FILE_OLDER;

	return verdict;
}

bool
fsutil_mount_overlay(const char *lowerdir, const char *upperdir, const char *workdir, const char *target)
{
	char options[3 * PATH_MAX];
	int flags = 0;

	if (upperdir == NULL) {
		snprintf(options, sizeof(options), "lowerdir=%s", lowerdir);
		flags |= MS_RDONLY;
	} else {
		snprintf(options, sizeof(options), "lowerdir=%s,upperdir=%s,workdir=%s",
				lowerdir, upperdir, workdir);

		/* Try to avoid nasty messages in dmesg */
		if (access(upperdir, W_OK) < 0) {
			trace("Looks like I'm not allowed to write to upperdir %s - mount overlay r/o", upperdir);
			flags |= MS_RDONLY;
		}
	}

	flags |= MS_LAZYTIME | MS_NOATIME;

	if (mount("wormhole", target, "overlay", flags, options) < 0) {
		log_error("Cannot mount overlayfs at %s: %m", target);
		trace("Options string was \"%s\"", options);
		return false;
	}

	trace2("mounted overlay of %s and %s to %s", lowerdir, upperdir, target);
	return true;
}

bool
fsutil_mount_bind(const char *source, const char *target, bool recursive)
{
	int flags = MS_BIND;

	if (recursive)
		flags |= MS_REC;

	if (mount(source, target, NULL, flags, NULL) < 0) {
		log_error("Unable to bind mount %s to %s: %m", source, target);
		return false;
	}

	trace2("bind mounted %s to %s", source, target);
	return true;
}

bool
fsutil_mount_virtual_fs(const char *where, const char *fstype, const char *options)
{
	int flags = 0;

	trace("Mounting %s at %s\n", fstype, where);
	if (mount(fstype, where, fstype, flags, options) < 0) {
		log_error("Unable to mount %s file system to %s: %m", fstype, where);
		return false;
	}

	trace2("mounted %s to %s", fstype, where);
	return true;
}

bool
fsutil_mount_tmpfs(const char *where)
{
	trace("Mounting tmpfs at %s\n", where);
	if (mount("tmpfs", where, "tmpfs", 0, NULL) < 0)
		return false;

	return true;
}

bool
fsutil_lazy_umount(const char *path)
{
	trace("Unmounting %s\n", path);
	if (umount2(path, MNT_DETACH) < 0) {
                log_error("Unable to unmount %s: %m", path);
		return false;
	}

	return true;
}

bool
fsutil_make_fs_private(const char *dir, bool maybe_in_chroot)
{
	if (mount("none", dir, NULL, MS_REC|MS_PRIVATE, NULL) == -1) {
		if (errno == EINVAL && maybe_in_chroot) {
			log_warning("Cannot change filesystem propagation of \"%s\" to private: %m", dir);
			log_warning("Probably running in a chroot; proceeding with caution");
			return true;
		}

		log_error("Cannot change filesystem propagation of \"%s\" to private: %m", dir);
		return false;
	}

	return true;
}

const char *
fsutil_get_filesystem_type(const char *path)
{
	static char unknown[16];
	struct statfs st;

	if (statfs(path, &st) < 0) {
		log_error("Failed to statfs %s: %m", path);
		return NULL;
	}

	switch (st.f_type) {
	case EXT4_SUPER_MAGIC:
		return "ext4";
	case BTRFS_SUPER_MAGIC:
		return "btrfs";
	case TMPFS_MAGIC:
		return "tmpfs";
	case XFS_SUPER_MAGIC:
		return "xfs";
	}

	snprintf(unknown, sizeof(unknown), "fstype-%lu", (long) st.f_type);
	return unknown;
}

void
pathutil_parser_init(struct pathutil_parser *parser, const char *relative_path)
{
	memset(parser, 0, sizeof(*parser));

	if (strlen(relative_path) >= sizeof(parser->pathbuf)) {
		log_error("%s: path too long\n", relative_path);
		return;
	}

	parser->relative_path = relative_path;
	parser->pos = relative_path;
}

bool
pathutil_parser_next(struct pathutil_parser *parser)
{
	const char *src;
	char *dst, *end;
	unsigned int n;

	if ((src = parser->pos) == NULL)
		return false;

	while (*src == '/')
		++src;
	if (*src == '\0')
		return false;

	dst = parser->namebuf;
	end = parser->namebuf + sizeof(parser->namebuf);
	while (*src && *src != '/') {
		if (dst + 1 >= end) {
			log_error("path component too long\n");
			return false;
		}
		*dst++ = *src++;
	}
	*dst = '\0';

	n = src - parser->relative_path;
	assert(n < sizeof(parser->pathbuf));

	memcpy(parser->pathbuf, parser->relative_path, n);
	parser->pathbuf[n] = '\0';

	parser->pos = src;
	return true;
}

void
strutil_set(char **var, const char *value)
{
	if (*var) {
		free(*var);
		*var = NULL;
	}

	if (value)
		*var = strdup(value);
}

bool
strutil_equal(const char *s1, const char *s2)
{
	if (!s1 || !s2)
		return s1 == s2;

	return !strcmp(s1, s2);
}

void
strutil_array_init(struct strutil_array *array)
{
	memset(array, 0, sizeof(*array));
}

void
strutil_array_append(struct strutil_array *array, const char *value)
{
	static const unsigned int chunk_size = 8;

	if (array->count == 0) {
		array->data = calloc(chunk_size, sizeof(array->data[0]));
	} else
	if ((array->count % chunk_size) == 0) {
		char **new_data;

		new_data = realloc(array->data, (array->count + chunk_size) * sizeof(array->data[0]));
		if (new_data == NULL)
			log_fatal("%s: memory allocation failed", __func__);
		array->data = new_data;
	}

	array->data[array->count++] = strdup(value);
}

void
strutil_array_append_array(struct strutil_array *dst, const struct strutil_array *src)
{
	unsigned int i;

	for (i = 0; i < src->count; ++i)
		strutil_array_append(dst, src->data[i]);
}

void
strutil_array_destroy(struct strutil_array *array)
{
	unsigned int i;

	for (i = 0; i < array->count; ++i)
		free(array->data[i]);
	if (array->data == NULL)
		free(array->data);

	memset(array, 0, sizeof(*array));
}
