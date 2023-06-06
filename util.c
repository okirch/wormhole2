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
#include <ctype.h>
#include <wordexp.h>
#include <stdarg.h>

#include "tracing.h"
#include "util.h"

struct dev_ino_array {
	unsigned int		count;
	struct {
		dev_t		dev;
		ino_t		ino;
	} *data;
};


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

const char *
pathutil_toplevel_dirname(const char *path)
{
	static char buffer[PATH_MAX];
	char *s, *tld;

	strncpy(buffer, path, sizeof(buffer));

	tld = buffer;
	for (s = buffer; *s == '/'; ++s)
		tld = s;

	/* No top-level dir name for root */
	if (*s == '\0')
		return NULL;

	s[strcspn(s, "/")] = '\0';
	return tld;
}

/*
 * Sanitize path.
 * Compress repeated / and remove trailing ones.
 */
char *
pathutil_sanitize(const char *path)
{
	char result[PATH_MAX + 10];
	char *s;

	if (strlen(path) >= PATH_MAX) {
		log_error("%s: path too long", __func__);
		return NULL;
	}
	if (*path == '\0')
		return NULL;

	s = result;

	while (*path) {
		if (*path == '/') {
			while (*path == '/')
				++path;
			if (*path == '\0')
				break;
			*s++ = '/';
		}

		while (*path && *path != '/')
			*s++ = *path++;

	}
	if (s == result)
		*s++ = '/';
	*s++ = '\0';

	assert(s < result + sizeof(result));
	return strdup(result);
}

void
pathutil_concat2(char **path_p, const char *parent, const char *name)
{
	static char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", parent, name);

	strutil_set(path_p, NULL);
	*path_p = pathutil_sanitize(path);
}

/*
 * Do tilde expansion on path name
 */
char *
pathutil_expand(const char *orig_path, bool quiet)
{
	wordexp_t words;
	char *result = NULL;

	memset(&words, 0, sizeof(words));
	if (wordexp(orig_path, &words, WRDE_NOCMD) != 0) {
		if (!quiet)
			log_error("Cannot expand path \"%s\": %m", orig_path);
		return NULL;
	}

	if (words.we_wordc == 1) {
		result = strdup(words.we_wordv[0]);
	} else if (!quiet) {
		log_error("Path expansion of \"%s\" produced %u results", orig_path, words.we_wordc);
	}

	wordfree(&words);
	return result;
}

bool
pathutil_check_prefix(const char *path, const char *prefix)
{
	int plen = strlen(prefix);

	return !strncmp(path, prefix, plen)
	    && (path[plen] == '\0' || path[plen] == '/');
}

bool
pathutil_check_prefix_list(const char *path, const char *prefixes[])
{
	const char *prefix;

	while ((prefix = *prefixes++) != NULL) {
		if (pathutil_check_prefix(path, prefix))
			return true;
	}

	return false;
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

void
procutil_command_setenv(struct procutil_command *cmd, const char *name, const char *value)
{
	char envbuf[256];

	snprintf(envbuf, sizeof(envbuf), "%s=%s", name, value);
	strutil_array_append(&cmd->env, envbuf);
}

void
procutil_command_require_virtual_fs(struct procutil_command *cmd, const char *fstype, const char *mount_point,
			const char *options, int flags)
{
	fsutil_mount_detail_t *detail;

	detail = fsutil_mount_detail_new(fstype, fstype, options);
	detail->flags = flags;

	fsutil_mount_req_array_append(&cmd->mounts, mount_point, detail);
	fsutil_mount_detail_release(detail);
}

void
procutil_command_destroy(struct procutil_command *cmd)
{
	fsutil_mount_req_array_destroy(&cmd->mounts);
	strutil_array_destroy(&cmd->env);
	memset(cmd, 0, sizeof(*cmd));
}

bool
procutil_command_exec(struct procutil_command *cmd, const char *command)
{
	unsigned int i;

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
			log_warning("Unable to chdir to %s: %m", cmd->working_directory);
			(void) chdir("/");
		}
	}

	for (i = 0; i < cmd->mounts.count; ++i) {
		fsutil_mount_req_t *mr = &cmd->mounts.data[i];

		/* We get here when we're asked to mount /proc or /dev/pts,
		 * which are sensitive to which namespace their attached.
		 * However, we may have previously performed a recursive
		 * bind on /dev, which also caused /dev/pts to get mounted.
		 * Get rid of this first */
		(void) umount2(mr->mount_point, MNT_DETACH);

		if (!fsutil_mount_request(mr)) {
			log_error("Unable to mount %s: %m", mr->mount_point);
			exit(70);
		}
	}

	for (i = 0; i < cmd->env.count; ++i) {
		putenv(cmd->env.data[i]);
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

bool
wormhole_create_init_namespace(void)
{
	if (unshare(CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWUTS) < 0) {
		log_error("unshare() failed: %m");
		return false;
	}

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

int
procutil_fork_and_wait(int *exit_status)
{
	int status;
	pid_t pid;

	pid = fork();
	if (pid < 0)
		log_fatal("Unable to fork: %m");

        if (pid == 0)
		return PROCUTIL_CHILD;

        if (!procutil_wait_for(pid, &status)) {
                log_error("Sub-process disappeared?");
                return PROCUTIL_CRASHED;
        }

        if (!procutil_get_exit_status(status, exit_status)) {
                log_error("Sub-process %s", procutil_child_status_describe(status));
                return PROCUTIL_CRASHED;
        }

	return PROCUTIL_EXITED;
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
__fsutil_tempdir_unmount(struct fsutil_tempdir *td)
{
	if (umount2(td->path, MNT_DETACH) < 0 && errno != EACCES) {
                trace("Unable to unmount %s: %m", td->path);
		return false;
	}
	td->mounted = false;
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
	if (creatfn(path, mode) == 0)
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

	if (createfn(path, mode) == 0)
		return true;

	if (errno == EEXIST) {
		if (chmod(path, mode) < 0) {
			if (errno == EROFS) {
				log_warning("cannot change mode on %s: %m", path);
				return true;
			}
			log_error("cannot change mode on %s: %m", path);
			return false;
		}
		return true;
	}

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

const char *
fsutil_makedir2(const char *parent, const char *name)
{
        const char *path = __pathutil_concat2(parent, name);

        if (!fsutil_makedirs(path, 0755)) {
                log_error("Unable to create %s: %m\n", path);
                return NULL;
	}

        return path;
}

const char *
fsutil_makefile2(const char *parent, const char *name)
{
        const char *path = __pathutil_concat2(parent, name);

        if (!fsutil_makefile(path, 0644)) {
                log_error("Unable to create file %s: %m\n", path);
                return NULL;
	}

        return path;
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
fsutil_isblk(const char *path)
{
	struct stat stb;

	if (lstat(path, &stb) < 0)
		return false;

	return !!S_ISBLK(stb.st_mode);
}

bool
__fsutil_is_whiteout(const struct stat *st)
{
	return st->st_mode == S_IFCHR && st->st_rdev == 0;
}

int
__fsutil_get_dtype(const struct stat *st)
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

const char *
fsutil_dtype_as_string(int dtype)
{
        switch (dtype) {
        case DT_REG:
                return "regular file";
        case DT_DIR:
                return "directory";
        case DT_LNK:
                return "symbolic link";
        case DT_CHR:
                return "character device";
        case DT_BLK:
                return "block device";
        case DT_SOCK:
                return "socket";
        case DT_FIFO:
                return "FIFO";
        default:
                break;
	}
        return "unknown fs object";
}

int
fsutil_get_dtype(const char *path)
{
	struct stat stb;

	if (lstat(path, &stb) < 0)
		return -1;

	return __fsutil_get_dtype(&stb);
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

/*
 * Array of dev/inode number
 */
void
dev_ino_array_append(struct dev_ino_array *a, dev_t dev, ino_t ino)
{
	if ((a->count % 64) == 0)
		a->data = realloc(a->data, (a->count + 64) * sizeof(a->data[0]));
	a->data[a->count].dev = dev;
	a->data[a->count].ino = ino;
	a->count++;
}

void
dev_ino_array_destroy(struct dev_ino_array *a)
{
	if (a->data)
		free(a->data);
	memset(a, 0, sizeof(*a));
	free(a);
}

bool
dev_ino_array_contains(const struct dev_ino_array *a, dev_t dev, ino_t ino)
{
	unsigned int i;

	for (i = 0; i < a->count; ++i) {
		if (a->data[i].dev == dev && a->data[i].ino == ino)
			return true;
	}
	return false;
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

struct fsutil_ftw_level {
	struct fsutil_ftw_level *parent;
	char			path[PATH_MAX];
	struct stat		dir_stat;
	int			dir_fd;
	DIR *			dir_handle;

	const struct dirent *	saved_dirent;

	struct fsutil_ftw_sorted_entries {
		unsigned int	pos;
		unsigned int	count;
		struct dirent **entries;
	} *sorted;
};

struct fsutil_ftw_ctx {
	const char *		top_dir;
	unsigned int		top_dir_len;

	fsutil_ftw_cb_fn_t *	user_callback;
	void *			user_closure;

	int			flags;
	bool			callback_before;
	bool			callback_after;

	dev_t			fsdev;
	struct dev_ino_array	exclude;

	struct fsutil_ftw_level	*current;
};

static struct fsutil_ftw_level *
fsutil_ftw_level_new(struct fsutil_ftw_level *parent, const char *name)
{
	const char *parent_path = parent->path;
	struct fsutil_ftw_level *child;
	struct stat child_stb;

	if (fstatat(parent->dir_fd, name, &child_stb, AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW) < 0) {
		log_error("can't stat %s/%s: %m", parent->path, name);
		return NULL;
	}

	child = calloc(1, sizeof(*child));
	snprintf(child->path, sizeof(child->path), "%s/%s", parent_path, name);
	child->dir_stat = child_stb;
	child->dir_fd = -1;

	return child;
}

static struct fsutil_ftw_level *
fsutil_ftw_level_new_top(const char *path)
{
	struct fsutil_ftw_level *dir;
	struct stat dir_stb;

	if (stat(path, &dir_stb) < 0) {
		log_error("can't stat %s: %m", path);
		return NULL;
	}

	dir = calloc(1, sizeof(*dir));
	strncpy(dir->path, path, sizeof(dir->path));
	dir->dir_stat = dir_stb;
	dir->dir_fd = -1;

	return dir;
}

static void
fsutil_ftw_level_free(struct fsutil_ftw_level *dir)
{
	if (dir->dir_fd >= 0) {
		close(dir->dir_fd);
		dir->dir_fd = -1;
	}

	if (dir->dir_handle) {
		closedir(dir->dir_handle);
		dir->dir_handle = NULL;
	}

	if (dir->sorted) {
		struct fsutil_ftw_sorted_entries *sorted = dir->sorted;
		unsigned int i;

		for (i = 0; i < sorted->count; ++i)
			free(sorted->entries[i]);
		free(sorted->entries);
		sorted->entries = NULL;
		sorted->count = 0;

		dir->sorted = NULL;
		free(sorted);
	}

	free(dir);
}

static struct fsutil_ftw_level *
fsutil_ftw_ctx_push(struct fsutil_ftw_ctx *ctx, struct fsutil_ftw_level *child)
{
	if (child != NULL) {
		child->parent = ctx->current;
		ctx->current = child;
	}
	return child;
}

static struct fsutil_ftw_level *
fsutil_ftw_ctx_pop(struct fsutil_ftw_ctx *ctx)
{
	struct fsutil_ftw_level *child;

	if ((child = ctx->current) != NULL) {
		ctx->current = child->parent;
		child->parent = NULL;
	}
	return child;
}

void
fsutil_ftw_ctx_free(struct fsutil_ftw_ctx *ctx)
{
	while (fsutil_ftw_ctx_pop(ctx))
		;

	free(ctx);
}

int
fsutil_ftw_descend(struct fsutil_ftw_ctx *ctx, const struct dirent *d)
{
	struct fsutil_ftw_level *parent = ctx->current;
	const char *name = d->d_name;
	struct fsutil_ftw_level *child;
	int childfd;
	int rv = FTW_ERROR;

	if (!(child = fsutil_ftw_level_new(parent, name)))
		return FTW_ERROR;
	child->saved_dirent = d;

	if (ctx->flags & FSUTIL_FTW_ONE_FILESYSTEM) {
		if (child->dir_stat.st_dev != ctx->fsdev) {
			trace("Skipping %s: different filesystem", child->path);
			goto skipped;
		}
	}

	if (ctx->exclude.count) {
		struct stat stb;

		if (lstat(child->path, &stb) < 0) {
			log_error("funny, %s disappeared", child->path);
			goto skipped;
		}

		if (dev_ino_array_contains(&ctx->exclude, stb.st_dev, stb.st_ino))
			goto skipped;
	}

	childfd = openat(parent->dir_fd, name, O_RDONLY|O_NOCTTY|O_NONBLOCK|O_NOFOLLOW|O_DIRECTORY);
	if (childfd < 0 && errno == EACCES && (ctx->flags & FSUTIL_FTW_OVERRIDE_OPEN_ERROR)) {
		(void) fchmodat(parent->dir_fd, name, 0700, 0);
		childfd = openat(parent->dir_fd, name, O_RDONLY|O_NOCTTY|O_NONBLOCK|O_NOFOLLOW|O_DIRECTORY);
	}
	if (childfd < 0) {
		if (!(ctx->flags & FSUTIL_FTW_IGNORE_OPEN_ERROR)) {
			log_error("can't open %s: %m", child->path);
			goto error;
		}
		goto skipped;
	}

	child->dir_fd = childfd;

	if (!(child->dir_handle = fdopendir(dup(childfd)))) {
		log_error("cannot dup directory fd: %m");
		goto error;
	}

	fsutil_ftw_ctx_push(ctx, child);
	return FTW_CONTINUE;

return_no_descend:
	if (child)
		fsutil_ftw_level_free(child);
	return rv;

error:
	rv = FTW_ERROR;
	goto return_no_descend;

skipped:
	rv = FTW_SKIP;
	goto return_no_descend;
}

static const struct dirent *
__fsutil_ftw_next(struct fsutil_ftw_level *dir)
{
	struct fsutil_ftw_sorted_entries *sorted;

	if (dir == NULL)
		return NULL;

	if ((sorted = dir->sorted) != NULL) {
		if (sorted->pos >= sorted->count)
			return NULL;
		return sorted->entries[sorted->pos++];
	}

	if (dir->dir_handle == NULL)
		return NULL;

	return readdir(dir->dir_handle);
}

bool
fsutil_ftw_return(struct fsutil_ftw_ctx *ctx)
{
	struct fsutil_ftw_level *child;

	if (!(child = fsutil_ftw_ctx_pop(ctx)))
		return false;

	fsutil_ftw_level_free(child);
	return true;
}

static int
__fsutil_dirent_compare(const void *pa, const void *pb)
{
	const struct dirent *da = *(struct dirent **) pa;
	const struct dirent *db = *(struct dirent **) pb;

	return strcmp(da->d_name, db->d_name);
}

static bool
fsutil_ftw_sort(struct fsutil_ftw_level *dir)
{
	struct fsutil_ftw_sorted_entries *sorted;
	const struct dirent *d;

	sorted = calloc(0, sizeof(*sorted));

	while ((d = __fsutil_ftw_next(dir)) != NULL) {
		struct dirent *cloned_dirent;

		if ((sorted->count % 32) == 0) {
			sorted->entries = realloc(sorted->entries, (sorted->count + 32) * sizeof(sorted->entries[0]));
		}

		cloned_dirent = malloc(sizeof(*d));
		*cloned_dirent = *d;
		sorted->entries[sorted->count++] = cloned_dirent;
	}

	qsort(sorted->entries, sorted->count, sizeof(sorted->entries[0]), __fsutil_dirent_compare);
	dir->sorted = sorted;
	return true;
}

bool
fsutil_ftw_skip(struct fsutil_ftw_ctx *ctx, const struct fsutil_ftw_cursor *cursor)
{
	struct fsutil_ftw_level *dir = ctx->current;

	if (dir && !strcmp(cursor->path, dir->path))
		return fsutil_ftw_return(ctx);
	return false;
}

const struct dirent *
fsutil_ftw_next(struct fsutil_ftw_ctx *ctx, struct fsutil_ftw_cursor *cursor)
{
	const struct dirent *d = NULL;
	int rv = FTW_CONTINUE;

	if (cursor)
		cursor->d = NULL;

	//trace4("%s(%s/%s)", __func__, ctx->top_dir, ctx->current? ctx->current->path: "<none>");
	while (rv == FTW_CONTINUE || rv == FTW_SKIP) {
		struct fsutil_ftw_level *dir = ctx->current;

		if (dir == NULL)
			break;

		if ((d = __fsutil_ftw_next(dir)) == NULL) {
			if (ctx->callback_after && dir->saved_dirent) {
				d = dir->saved_dirent;
				dir->saved_dirent = NULL;

				/* FIXME: shouldn't we actually return the dentry here? */
			}

			if (!fsutil_ftw_return(ctx))
				return NULL;
			continue;
		}

		if (d->d_type == DT_DIR) {
			if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
				continue;

			rv = fsutil_ftw_descend(ctx, d);
			if (rv == FTW_SKIP)
				continue;

			if (ctx->flags & FSUTIL_FTW_SORTED)
				fsutil_ftw_sort(ctx->current);
		}

		if (rv == FTW_CONTINUE && ctx->callback_before) {
			if (cursor) {
				snprintf(cursor->path, sizeof(cursor->path), "%s/%s", dir->path, d->d_name);
				cursor->d = d;

				if (ctx->top_dir) {
					assert(!strncmp(cursor->path, ctx->top_dir, ctx->top_dir_len) && cursor->path[ctx->top_dir_len] == '/');
					cursor->relative_path = cursor->path + ctx->top_dir_len;
				} else {
					cursor->relative_path = cursor->path;
				}

				if (ctx->flags & FSUTIL_FTW_NEED_STAT) {
					if (lstat(cursor->path, &cursor->_st) < 0) {
						log_error("funny, %s disappeared", cursor->path);
						continue;
					}
					cursor->st = &cursor->_st;

					if (dev_ino_array_contains(&ctx->exclude, cursor->_st.st_dev, cursor->_st.st_ino)) {
						trace2("%s: skipped", cursor->path);
#if 0
						if (!fsutil_ftw_skip(ctx, cursor))
							log_warning("tried to skip %s but failed", cursor->path);
#endif
						continue;
					}
				}
			}
			return d;
		}
	}

	return NULL;
}

struct fsutil_ftw_ctx *
fsutil_ftw_open(const char *dir_path, int flags, const char *root_dir)
{
	struct fsutil_ftw_ctx *ctx;
	struct fsutil_ftw_level *dir;
	char *full_path = NULL;

	if (root_dir) {
		pathutil_concat2(&full_path, root_dir, dir_path);
		dir_path = full_path;
	}

	trace2("%s(%s)", __func__, dir_path);
	ctx = calloc(1, sizeof(*ctx));
	ctx->flags = flags;

	dir = fsutil_ftw_level_new_top(dir_path);
	if (dir == NULL)
		goto failed;

	if (root_dir) {
		unsigned int len;

		len = strlen(root_dir);
		while (len && root_dir[len - 1] == '/')
			--len;

		if (len == 1 && root_dir[0] == '/') {
			/* root_dir is really the fs root */
		} else {
			ctx->top_dir = root_dir;
			ctx->top_dir_len = len;
		}
	}

	fsutil_ftw_ctx_push(ctx, dir);
	ctx->fsdev = dir->dir_stat.st_dev;

	dir->dir_fd = open(dir_path, O_RDONLY|O_NOCTTY|O_NONBLOCK|O_NOFOLLOW|O_DIRECTORY);
	if (dir->dir_fd >= 0)
		dir->dir_handle = fdopendir(dup(dir->dir_fd));

	if (dir == NULL || dir->dir_handle == NULL) {
		if (!(flags & FSUTIL_FTW_IGNORE_OPEN_ERROR)) {
			log_error("unable to open dir %s: %m", dir_path);
			goto failed;
		}
	}

	if (ctx->flags & FSUTIL_FTW_SORTED)
		fsutil_ftw_sort(dir);

	if (flags & FSUTIL_FTW_DEPTH_FIRST)
		ctx->callback_after = true;
	else if (flags & FSUTIL_FTW_PRE_POST_CALLBACK)
		ctx->callback_after = ctx->callback_before = true;
	else
		ctx->callback_before = true;
	return ctx;

failed:
	if (ctx)
		fsutil_ftw_ctx_free(ctx);
	strutil_drop(&full_path);
	return NULL;
}

bool
fsutil_ftw_exclude(struct fsutil_ftw_ctx *ctx, const char *path)
{
	struct stat stb;

	if (lstat(path, &stb) < 0)
		return false;

	dev_ino_array_append(&ctx->exclude, stb.st_dev, stb.st_ino);
	ctx->flags |= FSUTIL_FTW_NEED_STAT;
	return true;
}

static int
__fsutil_ftw_do_callback(struct fsutil_ftw_ctx *ctx, const struct dirent *d, int extra_flags)
{
	struct fsutil_ftw_level *dir = ctx->current;

	if (d == NULL) {
		log_error("%s called with NULL dirent");
		return FTW_ERROR;
	}

	return ctx->user_callback(dir->path, d, ctx->flags | extra_flags, ctx->user_closure);
}

bool
fsutil_ftw(const char *dir_path, fsutil_ftw_cb_fn_t *callback, void *closure, int flags)
{
	struct fsutil_ftw_ctx *ctx;
	const struct dirent *d;
	int rv = FTW_CONTINUE;

	ctx = fsutil_ftw_open(dir_path, flags, NULL);
	if (ctx == NULL)
		return false;

	ctx->user_callback = callback;
	ctx->user_closure = closure;

	while (rv == FTW_CONTINUE) {
		if ((d = __fsutil_ftw_next(ctx->current)) == NULL) {
			if (ctx->callback_after && ctx->current && ctx->current->saved_dirent) {
				d = ctx->current->saved_dirent;
				ctx->current->saved_dirent = NULL;
				rv = __fsutil_ftw_do_callback(ctx, d, FSUTIL_FTW_POST_DESCENT);
			} else {
				rv = FTW_CONTINUE;
			}
			if (!fsutil_ftw_return(ctx))
				break;
			continue;
		}

		if (d->d_type == DT_DIR) {
			if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
				continue;
			if (ctx->callback_before)
				rv = __fsutil_ftw_do_callback(ctx, d, FSUTIL_FTW_PRE_DESCENT);

			if (rv == FTW_CONTINUE)
				rv = fsutil_ftw_descend(ctx, d);
			else if (rv == FTW_SKIP)
				rv = FTW_CONTINUE;
		} else {
			rv = __fsutil_ftw_do_callback(ctx, d, 0);
		}
	}

	fsutil_ftw_ctx_free(ctx);
	return (rv == FTW_CONTINUE);
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
		if (errno == EACCES) {
			(void) fchmod(dir_fd, 0755);
			if (unlinkat(dir_fd, d->d_name, flags) >= 0)
				goto success;
		}

		log_error("Cannot remove %s/%s: %m", dir_path, d->d_name);
		return FTW_ERROR;
	}

success:
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
fsutil_remove_empty_dir_and_parents(const char *dir_path, const char *root)
{
	static char buffer[PATH_MAX];

	strncpy(buffer, dir_path, sizeof(buffer));
	while (*buffer) {
		const char *path = buffer;
		char *slash;

		if (root)
			path = __pathutil_concat2(root, path);

		if (rmdir(path) < 0 && errno != ENOENT)
			break;

		if ((slash = strrchr(buffer, '/')) == NULL)
			break;

		while (slash > buffer && slash[-1] == '/')
			--slash;
		*slash = '\0';
	}

	return true;
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
fsutil_file_content_identical(const char *path1, const char *path2)
{
	int fd1 = -1, fd2 = -1;
	bool verdict = false;

	if ((fd1 = open(path1, O_RDONLY)) < 0)
		goto out;
	if ((fd2 = open(path2, O_RDONLY)) < 0)
		goto out;

	while (true) {
		char buffer1[8192], buffer2[8192];
		int count1, count2;

		count1 = read(fd1, buffer1, sizeof(buffer1));
		count2 = read(fd2, buffer2, sizeof(buffer2));
		if (count1 == 0 && count2 == 0)
			break;
		if (count1 < 0 || count1 != count2)
			goto out;

		if (memcmp(buffer1, buffer2, count1) != 0)
			goto out;
	}

	verdict = true;

out:
	if (fd1 >= 0)
		close(fd1);
	if (fd2 >= 0)
		close(fd2);
	return verdict;
}

bool
fsutil_mount_overlay(const char *lowerdir, const char *upperdir, const char *workdir, const char *target)
{
	struct fsutil_tempdir empty;
	char options[3 * PATH_MAX];
	int flags = 0;

	fsutil_tempdir_init(&empty);
	if (upperdir == NULL) {
		if (!fsutil_tempdir_mount(&empty))
			return false;

		snprintf(options, sizeof(options), "userxattr,lowerdir=%s:%s", fsutil_tempdir_path(&empty), lowerdir);
		flags |= MS_RDONLY;
	} else {
		snprintf(options, sizeof(options), "userxattr,lowerdir=%s,upperdir=%s,workdir=%s",
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
		fsutil_tempdir_cleanup(&empty);
		return false;
	}

	trace2("Successfully mounted overlay of %s and %s to %s", lowerdir, upperdir, target);
	fsutil_tempdir_cleanup(&empty);
	return true;
}

bool
fsutil_mount_bind(const char *source, const char *target, bool recursive)
{
	int flags = MS_BIND;

	if (recursive)
		flags |= MS_REC;

	if (mount(source, target, NULL, flags, NULL) < 0) {
		log_error("Unable to bind mount %s on %s: %m", source, target);
		return false;
	}

	trace2("Successfully bind mounted %s to %s", source, target);
	return true;
}

bool
fsutil_mount_move(const char *source, const char *target)
{
	if (mount(source, target, NULL, MS_MOVE, NULL) < 0) {
		log_error("Unable to move mount %s to %s: %m", source, target);
		return false;
	}

	trace2("Successfully moved mount %s to %s", source, target);
	return true;
}

bool
fsutil_mount_virtual_fs(const char *where, const char *fstype, const char *options)
{
	int flags = 0;

	if (mount(fstype, where, fstype, flags, options) < 0) {
		log_error("Unable to mount %s file system on %s: %m", fstype, where);
		return false;
	}

	trace2("Successfully mounted %s virtual file system on %s", fstype, where);
	return true;
}

bool
fsutil_mount_tmpfs(const char *where)
{
	trace("Mounting tmpfs at %s\n", where);
	if (mount("tmpfs", where, "tmpfs", 0, NULL) < 0)
		return false;

	trace2("Successfully mounted tmpfs on %s", where);
	return true;
}

bool
fsutil_mount(const char *device, const char *where, const char *fstype, const char *options, int flags)
{
	if (mount(device, where, fstype, flags, options) < 0) {
		log_error("Unable to mount %s file system on %s with options %s: %m", fstype, where, options);
		return false;
	}

	trace2("Successfully mounted %s file system %s on %s (options %s)", fstype, device, where, options);
	return true;
}

bool
fsutil_mount_request(const fsutil_mount_req_t *mr)
{
	fsutil_mount_detail_t *detail;

	if (!(detail = mr->detail) || !mr->mount_point) {
		log_error("%s: incomplete mount request", __func__);
		errno = EINVAL;
		return false;
	}

	return fsutil_mount(detail->fsname, mr->mount_point, detail->fstype, detail->options, detail->flags);
}

bool
fsutil_mount_command(const char *target, const char *root_path)
{
	const char *argv[3] = { "mount", target, NULL };
	struct procutil_command cmd;
	int status;

	procutil_command_init(&cmd, (char **) argv);
	cmd.root_directory = root_path;

	if (!procutil_command_run(&cmd, &status))
		return false;

	if (!procutil_child_status_okay(status)) {
		log_error("mount %s: %s", target, procutil_child_status_describe(status));
		return false;
	}

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

char *
fsutil_resolve_fsuuid(const char *uuid)
{
	char pathbuf[PATH_MAX], resolved_path[PATH_MAX];

	snprintf(pathbuf, sizeof(pathbuf), "/dev/disk/by-uuid/%s", uuid);
	if (realpath(pathbuf, resolved_path) == NULL)
		return NULL;

	return strdup(resolved_path);
}

bool
fsutil_mount_options_contain(const char *options, const char *word)
{
	char *copy, *s;
	bool found = false;

	if (options == NULL)
		return false;

	copy = strdup(options);
	for (s = strtok(copy, ","); s && !found; s = strtok(NULL, ","))
		found = !strcmp(s, word);

	free(copy);
	return found;
}

/*
 * mount details as found in fstab and mtab
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

void
fsutil_mount_detail_array_append(fsutil_mount_detail_array_t *a, fsutil_mount_detail_t *md)
{
	if ((a->count & 15) == 0) {
		a->data = realloc(a->data, (a->count + 16) * sizeof(a->data[0]));
	}

	a->data[a->count++] = fsutil_mount_detail_hold(md);
}

void
fsutil_mount_detail_array_destroy(fsutil_mount_detail_array_t *a)
{
	unsigned int i;

	for (i = 0; i < a->count; ++i)
		fsutil_mount_detail_release(a->data[i]);

	if (a->data)
		free(a->data);
	memset(a, 0, sizeof(*a));
}

void
fsutil_mount_req_destroy(fsutil_mount_req_t *mr)
{
	if (mr->detail) {
		fsutil_mount_detail_release(mr->detail);
		mr->detail = NULL;
	}
	strutil_drop(&mr->mount_point);
}

void
fsutil_mount_req_array_append(fsutil_mount_req_array_t *a, const char *mount_point, fsutil_mount_detail_t *detail)
{
	fsutil_mount_req_t *mr;

	if ((a->count & 15) == 0) {
		a->data = realloc(a->data, (a->count + 16) * sizeof(a->data[0]));
	}

	mr = &a->data[a->count++];
	memset(mr, 0, sizeof(*mr));

	strutil_set(&mr->mount_point, mount_point);
	mr->detail = fsutil_mount_detail_hold(detail);
}

void
fsutil_mount_req_array_destroy(fsutil_mount_req_array_t *a)
{
	unsigned int i;

	for (i = 0; i < a->count; ++i)
		fsutil_mount_req_destroy(&a->data[i]);

	if (a->data)
		free(a->data);
	memset(a, 0, sizeof(*a));
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

bool
fsutil_copy_file(const char *system_path, const char *image_path, const struct stat *st)
{
	struct stat _st;
	char buffer[65536];
	unsigned long copied = 0;
	int srcfd = -1, dstfd = -1;
	int rcount;
	bool ok = false;

	if (st == NULL) {
		if (lstat(system_path, &_st) < 0) {
			log_error("%s: unable to stat: %m", system_path);
			return false;
		}
		st = &_st;
	}

	srcfd = open(system_path, O_RDONLY);
	if (srcfd < 0) {
		log_error("%s: unable to open file: %m", system_path);
		return false;
	}

	unlink(image_path);

	dstfd = open(image_path, O_CREAT | O_WRONLY | O_TRUNC, st->st_mode & 0777);
	if (dstfd < 0) {
		if (errno == ENOENT) {
			const char *parent_path = pathutil_dirname(image_path);
			(void) fsutil_makedirs(parent_path, 0755);
			dstfd = open(image_path, O_CREAT | O_WRONLY | O_TRUNC, st->st_mode & 0777);
		}

		if (dstfd < 0) {
			log_error("%s: unable to create file: %m", image_path);
			close(srcfd);
			return false;
		}
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

	trace2("%s -> %s: copied %lu bytes", system_path, image_path, copied);
	ok = true;

failed:
	if (srcfd >= 0)
		close(srcfd);
	if (dstfd >= 0)
		close(dstfd);
	return ok;
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

char *
__strutil_trim(char *s)
{
	int n;

	while (isspace(*s))
		++s;

	n = strlen(s);
	while (n && isspace(s[n-1]))
		s[--n] = '\0';
	return s;
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

char *
strutil_array_join(const struct strutil_array *a, const char *sepa)
{
	unsigned int i, slen, tot_len;
	char *result, *s;

	if (a->count == 0)
		return strdup("");

	if (sepa == NULL)
		sepa = "";
	slen = strlen(sepa);

	for (i = 0, tot_len = 0; i < a->count; ++i)
		tot_len += strlen(a->data[i]);
	tot_len += (a->count - 1) * slen;

	result = malloc(tot_len + 1);
	for (i = 0, s = result; i < a->count; ++i) {
		unsigned int n  = strlen(a->data[i]);

		if (i) {
			memcpy(s, sepa, slen);
			s += slen;
		}
		memcpy(s, a->data[i], n);
		s += n;
	}
	*s++ = '\0';

	return result;
}

void
strutil_split(const char *string, const char *sepa, struct strutil_array *result)
{
	char *copy, *s, *next = NULL;
	unsigned int sepa_len;

	if (!string)
		return;

	if (!sepa || !(sepa_len = strlen(sepa))) {
		strutil_array_append(result, string);
		return;
	}

	next = copy = strdup(string);
	while ((s = strstr(next, sepa)) != NULL) {
		*s = '\0';

		strutil_array_append(result, next);
		next = s + sepa_len;
	}

	if (next)
		strutil_array_append(result, next);
}

/*
 * Sort string array
 */
static int
__strutil_array_member_cmp(const void *pa, const void *pb)
{
	const char *a = *(const char **) pa;
	const char *b = *(const char **) pb;

	return strcmp(a, b);
}

void
strutil_array_sort(struct strutil_array *a)
{
	qsort(a->data, a->count, sizeof(a->data[0]), __strutil_array_member_cmp);
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

bool
strutil_array_contains(const struct strutil_array *array, const char *s)
{
	unsigned int i;

	if (s == NULL)
		return false;

	for (i = 0; i < array->count; ++i) {
		if (!strcmp(array->data[i], s))
			return true;
	}

	return false;
}

void
strutil_mapping_init(strutil_mapping_t *map)
{
	memset(map, 0, sizeof(*map));
}

void
strutil_mapping_destroy(strutil_mapping_t *map)
{
	struct strutil_mapping_pair *entry = map->data;
	unsigned int i;

	for (i = 0; i < map->count; ++i, ++entry) {
		strutil_drop(&entry->key);
		strutil_drop(&entry->value);
	}

	if (map->data) {
		free(map->data);
		map->data = NULL;
	}

	memset(map, 0, sizeof(*map));
}

static struct strutil_mapping_pair *
strutil_mapping_get_entry(strutil_mapping_t *map, const char *key)
{
	struct strutil_mapping_pair *entry = map->data;
	unsigned int i;

	for (i = 0; i < map->count; ++i, ++entry) {
		if (!entry->key && !strcmp(entry->key, key))
			return entry;
	}
	return NULL;
}

static struct strutil_mapping_pair *
strutil_mapping_new_entry(strutil_mapping_t *map, const char *key)
{
	struct strutil_mapping_pair *entry;

	if ((map->count % 16) == 0)
		map->data = realloc(map->data, (map->count + 16) * sizeof(map->data[0]));

	entry = map->data + map->count++;
	memset(entry, 0, sizeof(*entry));
	strutil_set(&entry->key, key);
	return entry;
}

void
strutil_mapping_add(strutil_mapping_t *map, const char *key, const char *value)
{
	struct strutil_mapping_pair *entry = NULL;

	entry = strutil_mapping_get_entry(map, key);
	if (entry == NULL)
		entry = strutil_mapping_new_entry(map, key);

	strutil_set(&entry->value, value);
}

void
strutil_mapping_add_no_override(strutil_mapping_t *map, const char *key, const char *value)
{
	struct strutil_mapping_pair *entry = NULL;

	entry = strutil_mapping_get_entry(map, key);
	if (entry != NULL)
		return;

	entry = strutil_mapping_new_entry(map, key);
	strutil_set(&entry->value, value);
}

/*
 * dynamic string buffer
 */
void
strutil_dynstr_init(struct strutil_dynstr *ds)
{
	memset(ds, 0, sizeof(*ds));
}

void
strutil_dynstr_destroy(struct strutil_dynstr *ds)
{
	strutil_drop(&ds->_value);
	memset(ds, 0, sizeof(*ds));
}

void
strutil_dynstr_reserve(struct strutil_dynstr *ds, unsigned int count)
{
	unsigned int new_size, required;

	assert(ds->_len <= ds->_size);

	if (count <= ds->_size - ds->_len)
		return;

	required = ds->_len + count;

	new_size = ds->_size;
	if (new_size == 0)
		new_size = 16;
	while (new_size < 1024 && new_size < count)
		new_size *= 2;

	if (new_size < required)
		new_size = (required + 1023) & ~1023;

	ds->_value = realloc(ds->_value, new_size);
	ds->_size = new_size;
}

void
strutil_dynstr_putc(struct strutil_dynstr *ds, char cc)
{
	if (cc == '\0')
		return;

	strutil_dynstr_reserve(ds, 1);
	ds->_value[ds->_len++] = cc;
	ds->_value[ds->_len] = '\0';
}

void
strutil_dynstr_append(struct strutil_dynstr *ds, const char *s)
{
	unsigned int n;

	if (!s || !*s)
		return;

	n = strlen(s);
	strutil_dynstr_reserve(ds, n);

	memcpy(ds->_value + ds->_len, s, n + 1);
	ds->_len += n;
}

void
strutil_dynstr_appendf(struct strutil_dynstr *ds, const char *fmt, ...)
{
	va_list ap;
	char *s;

	va_start(ap, fmt);
	vasprintf(&s, fmt, ap);
	va_end(ap);

	strutil_dynstr_append(ds, s);
	free(s);
}

const char *
strutil_dynstr_value(const struct strutil_dynstr *ds)
{
	return ds->_value;
}
