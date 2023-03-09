/*
 * wormhole
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

#include "wormhole2.h"
#include "paths.h"
#include "tracing.h"
#include "util.h"

static unsigned int	num_mounted;
bool			wormhole_in_chroot = false;

static bool
__mount_bind(const char *src, const char *dst, int extra_flags)
{
	trace("Binding %s to %s\n", src, dst);
	if (mount(src, dst, NULL, MS_BIND | extra_flags, NULL) < 0) {
		log_error("Unable to bind mount %s on %s: %m\n", src, dst);
		return false;
	}
	return true;
}

static char *
concat_path(const char *parent, const char *name)
{
	const char *path = __fsutil_concat2(parent, name);

	if (path)
		return strdup(path);
	return NULL;
}

static struct mount_bind *
mount_bind_new(struct mount_farm *farm, const char *src, const char *dst)
{
	struct mount_bind *bind;

	bind = calloc(1, sizeof(*bind));
	bind->source = strdup(src);
	bind->dest = strdup(dst);

	bind->next = farm->binds;
	farm->binds = bind;

	return bind;
}

static void
mount_bind_free(struct mount_bind *bind)
{
	strutil_drop(&bind->source);
	strutil_drop(&bind->dest);
}

void
mount_farm_print_tree(struct mount_farm *farm)
{
	mount_tree_print(farm->root);
}
void
mount_farm_free(struct mount_farm *farm)
{
	struct mount_leaf *root;
	struct mount_bind *bind;

	if ((root = farm->root) != NULL) {
		mount_leaf_free(root);
		farm->root = NULL;
	}

	while ((bind = farm->binds) != NULL) {
		farm->binds = bind->next;
		mount_bind_free(bind);
	}

	strutil_drop(&farm->upper_base);
	strutil_drop(&farm->work_base);
	strutil_drop(&farm->chroot);

	free(farm);
}


static struct mount_farm *
mount_farm_new(const char *farm_root)
{
	struct mount_farm *farm;

	farm = calloc(1, sizeof(*farm));
	farm->root = mount_leaf_new("", "/");

	(void) fsutil_makedirs(farm_root, 0755);

	pathutil_concat2(&farm->upper_base, farm_root, "upper");
	pathutil_concat2(&farm->work_base, farm_root, "work");
	pathutil_concat2(&farm->chroot, farm_root, "root");

	return farm;
}

bool
mount_farm_create_workspace(struct mount_farm *farm)
{
	if (!fsutil_makedirs(farm->upper_base, 0755)
	 || !fsutil_makedirs(farm->work_base, 0755)
	 || !fsutil_makedirs(farm->chroot, 0755))
		return false;

	return true;
}

bool
mount_farm_set_upper_base(struct mount_farm *farm, const char *upper_base)
{
	const char *fstype;

	if (!fsutil_makedirs(upper_base, 0755)) {
		log_error("Cannot use %s as base for upper layer: not a directory", upper_base);
		return false;
	}

	fstype = fsutil_get_filesystem_type(upper_base);
	if (strcmp(fstype, "btrfs")
	 && strcmp(fstype, "ext4")
	 && strcmp(fstype, "xfs")
	 && strcmp(fstype, "tmpfs")) {
		log_warning("%s is on a %s file system, and I'm not sure whether it can be used in overlayfs mounts",
				upper_base, fstype);
		log_warning("Things may or may not work.");
	}

	strutil_set(&farm->upper_base, fsutil_makedir2(upper_base, "image"));
	strutil_set(&farm->work_base, fsutil_makedir2(upper_base, "work"));

	return farm->upper_base && farm->work_base;
}

struct mount_leaf *
mount_farm_find_leaf(struct mount_farm *farm, const char *relative_path)
{
	return mount_leaf_lookup(farm->root, relative_path, false);
}

bool
mount_farm_has_mount_for(struct mount_farm *farm, const char *path)
{
	struct mount_leaf *leaf;

	if (!(leaf = mount_leaf_lookup(farm->root, path, false)))
		return false;

	return mount_leaf_is_mountpoint(leaf);
}

static struct mount_leaf *
mount_farm_add_system_dir(struct mount_farm *farm, const char *system_path)
{
	struct mount_leaf *leaf;

	if (!(leaf = mount_leaf_lookup(farm->root, system_path, true)))
		return NULL;

	if (!mount_leaf_set_fstype(leaf, "overlay", farm))
		return NULL;

	if (!mount_leaf_add_lower(leaf, system_path))
		return NULL;

	return leaf;
}

struct mount_leaf *
mount_farm_add_virtual_mount(struct mount_farm *farm, const char *system_path, const char *fstype)
{
	struct mount_leaf *leaf;

	if (!(leaf = mount_leaf_lookup(farm->root, system_path, true)))
		return NULL;

	if (!mount_leaf_set_fstype(leaf, fstype, farm))
		return NULL;

	return leaf;
}

static struct mount_bind *
mount_farm_add_bind(struct mount_farm *farm, const char *src, const char *dst)
{
	struct mount_bind *bind;

	bind = mount_bind_new(farm, src, dst);
	return bind;
}

struct mount_leaf *
mount_farm_add_leaf_readonly(struct mount_farm *farm, const char *relative_path)
{
	struct mount_leaf *leaf;

	leaf = mount_farm_add_system_dir(farm, relative_path);
	if (leaf)
		leaf->readonly = true;
	return leaf;
}

static bool
__mount_farm_mount_leaf(const struct mount_leaf *leaf)
{
	if (leaf->fstype == NULL)
		return true;

	if (!mount_leaf_mount(leaf))
		return false;

	num_mounted++;
	return true;
}

static bool
mount_farm_mount_all(struct mount_farm *farm)
{
	struct mount_bind *bind;

	num_mounted = 0;

	if (!mount_leaf_traverse(farm->root, __mount_farm_mount_leaf))
		return false;

	for (bind = farm->binds; bind; bind = bind->next) {
		if (!__mount_bind(bind->source, bind->dest, MS_REC))
			return false;
	}

	farm->num_mounts = num_mounted;
	return true;
}

/*
 * We want a file or directory to appear in the utility's environment.
 *
 * We first ensure that there is a mount point in the upperdir.
 * Then, after the overlayfs has been assembled, we mount the source object
 * inside the final tree.
 */
bool
mount_farm_mount_into(struct mount_farm *farm, const char *src, const char *dst)
{
	const char *loc, *mount;

	/* Create the node on which we later bind the file */
	if (fsutil_isdir(src))
		loc = fsutil_makedir2(farm->upper_base, dst);
	else
		loc = fsutil_makefile2(farm->upper_base, dst);
	if (loc == NULL)
		return false;

	if (chown(loc, 0, 0))
		log_warning("Unable to chown %s: %m", loc);

	mount = fsutil_makedir2(farm->chroot, dst);

	trace("Setting up %s with binding to %s", mount, src);
	return mount_farm_add_bind(farm, src, mount) != NULL;
}

bool
mount_farm_bind_system_dir(struct mount_farm *farm, const char *system_path)
{
	if (!mount_farm_add_bind(farm, system_path, system_path))
		return false;

	/* This causes the discovery code to not descend into /proc and friends 
	 * even in the run case. */
	return mount_farm_add_virtual_mount(farm, system_path, "hidden");
}

static int
__mount_layer_discover_callback(const char *dir_path, const struct dirent *d, int flags, void *closure)
{
	struct mount_state *state = closure;

	if (d->d_type == DT_UNKNOWN) {
		log_error("%s/%s: cannot handle unknown dtype\n", dir_path, d->d_name);
		return FTW_ERROR;
	}

	if (d->d_type == DT_DIR) {
		const char *full_path = __fsutil_concat2(dir_path, d->d_name);
		struct mount_leaf *leaf;

		if (!(leaf = mount_state_create_leaf(state, full_path))) {
			log_error("%s: cannot create tree node", full_path);
			return FTW_ERROR;
		}
	}

	return FTW_CONTINUE;
}

static struct mount_state *
mount_layer_discover(struct wormhole_layer *layer)
{
	const char *tree_path = layer->image_path;
	struct mount_state *state;
	bool okay = false;

	trace("%s(%s)", __func__, layer->image_path);

	/* Walk the directory tree below $layer/image */
	state = mount_state_new();
	okay = fsutil_ftw(tree_path, __mount_layer_discover_callback, state, FSUTIL_FTW_ONE_FILESYSTEM);

	/* Strip the $layer/image prefix off each node's relative_path */
	if (okay)
		okay = mount_state_make_relative(state, tree_path);

	if (!okay && state) {
		mount_state_free(state);
		state = NULL;
	}

	return state;
}

static bool
__mount_farm_discover_callback(void *closure, const char *mount_point,
                                const char *mnt_type,
                                const char *fsname)
{
	struct mount_state *state = closure;
	struct mount_leaf *leaf;

	if (!strncmp(mount_point, "/tmp/", 5)) {
		log_debug("Ignoring mount point %s\n", mount_point);
		return true;
	}

	leaf = mount_leaf_lookup(state->root, mount_point, true);
	if (leaf == NULL) {
		log_error("mount_leaf_lookup(%s) failed\n", mount_point);
		return false;
	}

	leaf->fstype = strdup(mnt_type);
	return true;
}

static struct mount_leaf *
mount_state_find(struct mount_state *state, const char *path)
{
	return mount_leaf_lookup(state->root, path, false);
}

static bool
mount_farm_discover_system_dir_with_submounts(struct mount_farm *farm, struct mount_leaf *to_be_exported, bool always_use_overlays)
{
	const char *dir_path = to_be_exported->relative_path;
	DIR *dir;
	struct dirent *d;
	bool okay = true;

	if (!(dir = opendir(dir_path))) {
		log_error("Cannot open %s: %m\n", dir_path);
		return false;
	}

	while (okay && (d = readdir(dir)) != NULL) {
		if (d->d_type == DT_UNKNOWN) {
			log_error("%s/%s: unknown\n", dir_path, d->d_name);
			closedir(dir);
			return false;
		}

		if (d->d_type == DT_DIR) {
			char *system_path;
			struct mount_leaf *child;

			if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
				continue;

			system_path = concat_path(dir_path, d->d_name);
			if (!always_use_overlays) {
				struct mount_leaf *mount_node;

				mount_node = mount_farm_find_leaf(farm, system_path);
				if (mount_node == NULL) {
					okay = mount_farm_mount_into(farm, system_path, system_path);
					goto next;
				}
			}

			if (mount_farm_has_mount_for(farm, system_path)) {
				trace("we already have a mount for %s", system_path);
				goto next;
			}

			child = mount_leaf_lookup(to_be_exported, d->d_name, false);
			if (child == NULL || child->children == NULL) {
				/* There is no mount point for this directory, and no mount point below it.
				 * Set up an overlay mount for this location.
				 */
				if (mount_farm_add_system_dir(farm, system_path) == NULL)
					okay = false;
			} else {
				trace("we do not yet have a mount for %s", child->relative_path);
				if (!mount_farm_discover_system_dir_with_submounts(farm, child, always_use_overlays))
					okay = false;
			}

next:
			free(system_path);
		} else {
			trace3("%s/%s: other type\n", dir_path, d->d_name);
		}
	}

	closedir(dir);
	return okay;
}

static bool
__mount_farm_discover_system_dir(struct mount_farm *farm, struct mount_state *state, const char *system_path, bool always_use_overlays)
{
	struct mount_leaf *leaf, *mounts;

	leaf = mount_farm_find_leaf(farm, system_path);
	if (leaf && mount_leaf_is_mountpoint(leaf)) {
		trace("%s: we already have a mount for %s\n", __func__, system_path);
		return true;
	}

	mounts = mount_state_find(state, system_path);
	if (mounts == NULL || mounts->children == NULL) {
		return mount_farm_add_system_dir(farm, system_path) != NULL;
	}

	trace("%s has child mounts\n", system_path);
	if (!mount_farm_discover_system_dir_with_submounts(farm, mounts, always_use_overlays))
		return false;

	return true;
}

static bool
mount_farm_discover_system_dir(struct mount_farm *farm, struct mount_state *state, const char *system_path)
{
	return __mount_farm_discover_system_dir(farm, state, system_path, true);
}

static bool
__mount_farm_apply_layer(struct mount_farm *farm, struct mount_leaf *farm_dir, struct mount_leaf *layer_dir)
{
	struct mount_leaf *layer_child, *farm_child;
	bool okay = true;

	for (layer_child = layer_dir->children; layer_child; layer_child = layer_child->next) {
		farm_child = mount_leaf_lookup(farm_dir, layer_child->name, false);
		if (farm_child == NULL) {
			log_error("Image provides %s in non-canonical location", layer_child->relative_path);
			return false;
		}

		if (farm_child->children == NULL) {
			/* Now we should add the directory $image/foo/bar as a lowerdir to the
			 * mount point of /foo/bar 
			 */
			okay = mount_leaf_add_lower(farm_child, layer_child->full_path);
		}
		else
			if (!__mount_farm_apply_layer(farm, farm_child, layer_child))
				return false;
	}

	return okay;
}

static bool
mount_farm_apply_layer(struct mount_farm *farm, struct mount_state *layer_state)
{
	return __mount_farm_apply_layer(farm, farm->root, layer_state->root);
}

bool
mount_farm_discover(struct mount_farm *farm, struct wormhole_layer_array *layers)
{
	struct mount_state *state = NULL;
	bool okay = false, use_overlays = true;
	unsigned int i;

	state = mount_state_new();

	if (!mount_state_discover(NULL, __mount_farm_discover_callback, state)) {
		log_error("Mount state discovery failed\n");
		goto out;
	}

	mount_farm_discover_system_dir(farm, state, "/etc");
	mount_farm_discover_system_dir(farm, state, "/bin");
	mount_farm_discover_system_dir(farm, state, "/sbin");
	mount_farm_discover_system_dir(farm, state, "/var");
	mount_farm_discover_system_dir(farm, state, "/lib");
	mount_farm_discover_system_dir(farm, state, "/lib64");
	mount_farm_discover_system_dir(farm, state, "/usr");

	for (i = 0; i < layers->count; ++i) {
		if (!mount_farm_apply_layer(farm, layers->data[i]->tree))
			goto out;
		use_overlays = false;
	}

	okay = __mount_farm_discover_system_dir(farm, state, "/", use_overlays);

out:
	if (state)
		mount_state_free(state);
	return okay;
}

bool
mount_farm_assemble_for_build(struct mount_farm *farm, struct wormhole_layer_array *layers)
{
	mount_farm_add_virtual_mount(farm, "/proc", "proc");
	mount_farm_add_virtual_mount(farm, "/sys", "sysfs");
	mount_farm_add_virtual_mount(farm, "/dev", "devpts");

	mount_farm_add_virtual_mount(farm, "/run", "tmpfs");
	mount_farm_add_virtual_mount(farm, "/boot", "hidden");

	if (!mount_farm_discover(farm, layers))
		return false;

	return true;
}

bool
mount_farm_assemble_for_run(struct mount_farm *farm, struct wormhole_layer_array *layers)
{
	bool okay = false;

	mount_farm_bind_system_dir(farm, "/proc");
	mount_farm_bind_system_dir(farm, "/sys");
	mount_farm_bind_system_dir(farm, "/dev");
	mount_farm_bind_system_dir(farm, "/run");
	mount_farm_add_virtual_mount(farm, "/boot", "hidden");

	okay = mount_farm_discover(farm, layers);
	return okay;
}

static int
perform_build(struct wormhole_context *ctx)
{
	int status, exit_status;

	log_info("Performing build:\n");
	if (!procutil_command_run(&ctx->command, &status)) {
		exit_status = 12;
	} else
	if (!procutil_get_exit_status(status, &exit_status)) {
		log_error("Command %s %s", ctx->command.argv[0], procutil_child_status_describe(status));
		exit_status = 13;
	} else {
		trace("Command exited with status %d\n", exit_status);
	}

	log_info("---\n");

	return exit_status;
}

static int
perform_use(void)
{
	system("ls -la /usr/lib/python3.6/site-packages/parse.py");
	system("ls -la /usr/lib/python3.6/site-packages/parse-*/");
	system("echo 'Counting files in site-packages'; ls -la /usr/lib/python3.6/site-packages/ | wc");
	return 0;
}

enum {
	PURPOSE_NONE,
	PURPOSE_BUILD,
	PURPOSE_USE,

	__PURPOSE_MESSING_AROUND,
};

bool
wormhole_layer_patch_rpmdb(struct wormhole_layer *layer, const char *rpmdb_orig)
{
	char cmdbuf[1024];

	snprintf(cmdbuf, sizeof(cmdbuf),
			"rpmhack --orig-root '%s' --patch-path '%s' patch %s",
			rpmdb_orig, layer->rpmdb_path, layer->image_path);
	trace("Executing %s", cmdbuf);

	if (system(cmdbuf) != 0) {
		log_error("Failed to patch RPM database for layer %s", layer->name);
		return false;
	}

	return true;
}

bool
wormhole_layer_diff_rpmdb(struct wormhole_layer *layer, const char *rpmdb_orig)
{
	char cmdbuf[1024];

	snprintf(cmdbuf, sizeof(cmdbuf),
			"rpmhack --orig-root '%s' --patch-path '%s' diff %s",
			rpmdb_orig, layer->rpmdb_path, layer->image_path);
	trace("Executing %s", cmdbuf);

	if (system(cmdbuf) != 0) {
		log_error("Failed to create RPM database diff for layer %s", layer->name);
		return false;
	}

	trace("Created RPM database diff %s", layer->rpmdb_path);
	return true;
}

void
wormhole_context_free(struct wormhole_context *ctx)
{
	fsutil_tempdir_cleanup(&ctx->temp);
	strutil_drop(&ctx->workspace);
	strutil_drop(&ctx->build_target);
	strutil_drop(&ctx->build_root);

	if (ctx->farm) {
		mount_farm_free(ctx->farm);
		ctx->farm = NULL;
	}

	wormhole_layer_array_destroy(&ctx->layers);

	free(ctx);
}

struct wormhole_context *
wormhole_context_new(void)
{
	struct wormhole_context *ctx;
	const char *workspace;

	ctx = calloc(1, sizeof(*ctx));
	ctx->purpose = PURPOSE_NONE;
	ctx->exit_status = 5;

	fsutil_tempdir_init(&ctx->temp);
	if (!(workspace = fsutil_tempdir_path(&ctx->temp))) {
		log_error("Unable to create temp space for wormhole\n");
		goto failed;
	}

	strutil_set(&ctx->workspace, workspace);

	if (getuid() == 0)
		ctx->use_privileged_namespace = true;

	if (!(ctx->farm = mount_farm_new(workspace)))
		goto failed;

	return ctx;

failed:
	wormhole_context_free(ctx);
	return NULL;
}

void
wormhole_context_set_build(struct wormhole_context *ctx, const char *name, const char *build_root)
{
	if (ctx->purpose != PURPOSE_NONE)
		log_fatal("Conflicting purposes for this wormhole\n");

	ctx->purpose = PURPOSE_BUILD;
	strutil_set(&ctx->build_target, name);

	if (build_root)
		strutil_set(&ctx->build_root, build_root);
	else
		strutil_set(&ctx->build_root, fsutil_makedir2(get_current_dir_name(), "wormhole-build"));

	if (ctx->build_root == NULL)
		log_fatal("Cannot set build root to $PWD/wormhole-build");
}


static bool
__wormhole_context_use_layer(struct wormhole_context *ctx, const char *name, unsigned int depth)
{
	struct wormhole_layer *layer;
	unsigned int i;

	if (depth > 100) {
		log_error("too many nested layers, possibly a circular reference");
		return false;
	}

	if (wormhole_layer_array_find(&ctx->layers, name))
		return true;

	layer = wormhole_layer_new(name, NULL, depth);

	if (!wormhole_layer_load_config(layer))
		goto failed;

	if (!(layer->tree = mount_layer_discover(layer))) {
		log_error("%s does not look like a valid wormhole layer", layer->path);
		goto failed;
	}

	/* Now resolve the lower layers referenced by this one */
	for (i = 0; i < layer->used.count; ++i) {
		if (!__wormhole_context_use_layer(ctx, layer->used.data[i], depth + 1))
			goto failed;
	}

	wormhole_layer_array_append(&ctx->layers, layer);
	return true;

failed:
	wormhole_layer_free(layer);
	return false;
}

bool
wormhole_context_use_layer(struct wormhole_context *ctx, const char *name)
{
	return __wormhole_context_use_layer(ctx, name, 0);
}

bool
wormhole_context_use_layers(struct wormhole_context *ctx, unsigned int count, const char **names)
{
	while (count--) {
		if (!wormhole_context_use_layer(ctx, *names++))
			return false;
	}

	return true;
}

void
wormhole_context_set_command(struct wormhole_context *ctx, char **argv)
{
	procutil_command_init(&ctx->command, argv);
}

/*
 * This is Major Tom to ground control; I'm stepping through the door ...
 */
static bool
wormhole_context_detach(struct wormhole_context *ctx)
{
	if (ctx->use_privileged_namespace) {
		if (!wormhole_create_namespace())
			return false;
	} else {
		if (!wormhole_create_user_namespace(true))
			return false;
	}

	if (!fsutil_make_fs_private("/", wormhole_in_chroot))
		return false;

	if (!fsutil_tempdir_mount(&ctx->temp))
		return false;

	return mount_farm_create_workspace(ctx->farm);
}

static bool
wormhole_context_mount_tree(struct wormhole_context *ctx)
{
	struct mount_farm *farm = ctx->farm;

	if (tracing_level > 0) {
		trace("Tree to be assembled:\n");
		mount_farm_print_tree(farm);
		trace("---\n");
	}

	if (!mount_farm_mount_all(farm))
		return false;

	trace("Mounted %u directories\n", farm->num_mounts);
	return true;
}


static bool
prepare_tree_for_building(struct wormhole_context *ctx)
{
	struct mount_farm *farm = ctx->farm;

	assert(ctx->build_root);

	if (!mount_farm_set_upper_base(farm, ctx->build_root))
		return false;

	if (!mount_farm_assemble_for_build(farm, &ctx->layers))
		return false;

	if (ctx->manage_rpmdb && ctx->layers.count) {
		const char *rpmdb_orig = RPMDB_PATH;
		unsigned int i;

		trace("Building RPM database");
		for (i = 0; i < ctx->layers.count; ++i) {
			if (!wormhole_layer_patch_rpmdb(ctx->layers.data[i], rpmdb_orig))
				return false;
		}
	}

	return true;
}

static bool
prepare_tree_for_use(struct wormhole_context *ctx)
{
	struct mount_farm *farm = ctx->farm;

	if (!mount_farm_assemble_for_run(farm, &ctx->layers))
		return false;

	return true;
}

/* Really ancient testing ground. */
bool
prepare_tree_for_messing_around(struct wormhole_context *ctx)
{
	fsutil_makedirs("/var/tmp/lalla/lower", 0755);
	fsutil_makedirs("/var/tmp/lalla/upper", 0755);
	fsutil_makedirs("/var/tmp/lalla/work", 0755);
	fsutil_makedirs("/var/tmp/lalla/root", 0755);
	fsutil_makedirs("/var/tmp/lalla/usr-local", 0755);

	system("grep /local /proc/mounts");
	if (mount("/usr/local", "/var/tmp/lalla/usr-local", NULL, MS_BIND|MS_REC, NULL) < 0)
		perror("fnord");
	system("grep /local /proc/mounts");
	if (umount("/usr/local") < 0)
		perror("fnord2");
	system("grep /local /proc/mounts");
	if (!__mount_bind("/usr", "/var/tmp/lalla/lower", 0))
		return false;
	system("ls /var/tmp/lalla/lower/local");
	if (!__mount_bind("/var/tmp/lalla/usr-local", "/var/tmp/lalla/lower/local", 0))
		return false;

	if (mount("wormhole", "/var/tmp/lalla/root", "overlay", MS_NOATIME|MS_LAZYTIME|MS_RDONLY,
			"lowerdir=/var/tmp/lalla/lower,upperdir=/var/tmp/lalla/upper,workdir=/var/tmp/lalla/work") < 0) {
		perror("mount overlay");
		return false;
	}

	return true;
}

static bool
wormhole_context_switch_root(struct wormhole_context *ctx)
{
	struct mount_farm *farm = ctx->farm;

	if (wormhole_in_chroot) {
		/* Not optimal. Any mounts will propagate, and will be
		 * visible even outside the chroot environment :-( */
		chdir(farm->chroot);
		if (chroot(farm->chroot) < 0) {
			perror("chroot");
			return 1;
		}
	} else {
		/* bind mount the chroot directory to /mnt, then clean up the temp dir. */
		if (!__mount_bind(farm->chroot, "/mnt", MS_REC))
			return 1;

		fsutil_tempdir_unmount(&ctx->temp);

		chdir("/mnt");
		if (chroot("/mnt") < 0) {
			perror("chroot");
			return 1;
		}
	}

	if (setgid(0) < 0)
		log_fatal("Failed to setgid(0): %m\n");
	if (setuid(0) < 0)
		log_fatal("Failed to setuid(0): %m\n");

	return true;
}

bool
wormhole_context_perform_in_container(struct wormhole_context *ctx, int (*fn)(struct wormhole_context *))
{
	int status;
	pid_t pid;

	pid = fork();
	if (pid < 0)
		log_fatal("Unable to fork: %m");

	if (pid == 0) {
		exit(fn(ctx));
	}

	if (!procutil_wait_for(pid, &status)) {
		log_error("Container sub-process disappeared?");
		return false;
	}

	if (!procutil_get_exit_status(status, &ctx->exit_status)) {
		log_error("Container sub-process failed");
		return false;
	}

	if (ctx->exit_status) {
		log_error("Container sub-process exited with status %d", ctx->exit_status);
		return false;
	}

	return true;
}

static int
__perform_build(struct wormhole_context *ctx)
{
	ctx->exit_status = 100;

	if (!wormhole_context_detach(ctx))
		goto out;

	if (!prepare_tree_for_building(ctx)
	 || !wormhole_context_mount_tree(ctx))
		goto out;

	if (!wormhole_context_switch_root(ctx))
		goto out;

	return perform_build(ctx);

out:
	return ctx->exit_status;
}

struct prune_ctx {
	char *			image_root;
	struct mount_farm *	mounts;
};

static int
__prune_callback(const char *dir_path, const struct dirent *d, int flags, void *closure)
{
	struct prune_ctx *prune = closure;
	const char *relative_path;
	char *full_path = NULL;
	struct mount_leaf *mount;

	if (d->d_type != DT_DIR)
		return FTW_CONTINUE;

	pathutil_concat2(&full_path, dir_path, d->d_name);

	if (!(relative_path = fsutil_strip_path_prefix(full_path, prune->image_root)))
		return FTW_ERROR;

	mount = mount_farm_find_leaf(prune->mounts, relative_path);
	if (mount) {
		bool try_to_prune = false;

		if (mount_leaf_is_mountpoint(mount)
		 || !mount_leaf_is_below_mountpoint(mount))
			try_to_prune = true;

		if (try_to_prune && rmdir(full_path) == 0)
			trace("Pruned %s", full_path);
	}

	strutil_drop(&full_path);
	return FTW_CONTINUE;
}


static int
__prune_build(struct wormhole_context *ctx)
{
	unsigned int saved_tracing_level = tracing_level;
	struct prune_ctx prune_ctx;

	tracing_set_level(0);
	if (!wormhole_context_detach(ctx))
		goto out;

	if (!prepare_tree_for_building(ctx))
		goto out;

	tracing_set_level(saved_tracing_level);

	prune_ctx.image_root = concat_path(ctx->build_root, "image");
	prune_ctx.mounts = ctx->farm;

	fsutil_ftw(prune_ctx.image_root, __prune_callback, &prune_ctx, FSUTIL_FTW_ONE_FILESYSTEM | FSUTIL_FTW_DEPTH_FIRST);

	return 0;

out:
	return 42;
}

static void
do_build(struct wormhole_context *ctx)
{
	struct wormhole_layer *layer;
	unsigned int i;

	if (!ctx->use_privileged_namespace) {
		log_error("Currently, you must be root to build wormhole layers\n");
		return;
	}

	if (!wormhole_context_perform_in_container(ctx, __perform_build))
		return;

	/* Now post-process the build. */
	if (!wormhole_context_perform_in_container(ctx, __prune_build))
		return;

	layer = wormhole_layer_new(ctx->build_target, ctx->build_root, 0);
	for (i = 0; i < ctx->layers.count; ++i) {
		struct wormhole_layer *used = ctx->layers.data[i];

		if (used->depth == 0)
			strutil_array_append(&layer->used, used->name);
	}

	if (ctx->manage_rpmdb) {
		const char *rpmdb_orig = RPMDB_PATH;

		if (ctx->layers.count)
			rpmdb_orig = ctx->layers.data[ctx->layers.count - 1]->rpmdb_path;
		if (!wormhole_layer_diff_rpmdb(layer, rpmdb_orig)) {
			log_error("Failed to create RPM database diff");
			return;
		}
	}

	if (!wormhole_layer_save_config(layer)) {
		log_error("Unable to write configuration for new layer");
		return;
	}

	log_info("New image can be found in %s", ctx->build_root);
	ctx->exit_status = 0;
}

static int
__run_container(struct wormhole_context *ctx)
{
	if (!wormhole_context_detach(ctx))
		goto out;

	if (!prepare_tree_for_use(ctx)
	 || !wormhole_context_mount_tree(ctx))
		goto out;

	if (!wormhole_context_switch_root(ctx))
		goto out;

	return perform_use();

out:
	return 42;
}

static void
do_run(struct wormhole_context *ctx)
{
	if (!wormhole_context_perform_in_container(ctx, __run_container))
		return;

	ctx->exit_status = 0;
}

enum {
	OPT_RPMDB = 256,
};

static struct option	long_options[] = {
	{ "debug",	no_argument,		NULL,	'd'		},
	{ "build",	required_argument,	NULL,	'B'		},
	{ "buildroot",	required_argument,	NULL,	'R'		},
	{ "use",	required_argument,	NULL,	'u'		},
	{ "rpmdb",	no_argument,		NULL,	OPT_RPMDB	},

	{ NULL },
};

int
main(int argc, char **argv)
{
	unsigned int opt_debug = 0;
	const char *opt_build = NULL;
	const char *opt_build_root = NULL;
	unsigned int opt_use_count = 0;
	const char *opt_use[LOWER_LAYERS_MAX];
	bool opt_rpmdb = false;
	struct wormhole_context *ctx;
	int exit_status = 1;
	int c;

	while ((c = getopt_long(argc, argv, "B:dR:u:", long_options, NULL)) != EOF) {
		switch (c) {
		case 'B':
			opt_build = optarg;
			break;

		case 'd':
			opt_debug += 1;
			break;

		case 'R':
			opt_build_root = optarg;
			break;

		case 'u':
			if (opt_use_count >= LOWER_LAYERS_MAX)
				log_fatal("Too many lower layers given");
			opt_use[opt_use_count++] = optarg;
			break;

		case OPT_RPMDB:
			opt_rpmdb = true;
			break;

		default:
			log_error("Unknown option\n");
			return 1;
		}
	}

	if (optind >= argc)
		log_fatal("Missing command to be executed\n");

	tracing_set_level(opt_debug);
	trace("debug level set to %u\n", tracing_level);

	if (!fsutil_dir_is_mountpoint("/")) {
		log_warning("Running inside what looks like a chroot environment.");
		wormhole_in_chroot = true;
	}

	ctx = wormhole_context_new();

	wormhole_context_set_command(ctx, argv + optind);
	ctx->manage_rpmdb = opt_rpmdb;

	if (!wormhole_context_use_layers(ctx, opt_use_count, opt_use))
		goto out;

	if (opt_build) {
		wormhole_context_set_build(ctx, opt_build, opt_build_root);

		do_build(ctx);
	} else {
		ctx->purpose = PURPOSE_USE;
		do_run(ctx);
	}


out:
	exit_status = ctx->exit_status;
	wormhole_context_free(ctx);

	return exit_status;
}
