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

#define BIND_SYSTEM_OVERLAYS	true

struct system_mount *
system_mount_new(const char *fstype, const char *fsname, const char *options)
{
	struct system_mount *sm;

	sm = calloc(1, sizeof(*sm));

	sm->refcount = 1;
	strutil_set(&sm->fstype, fstype);
	strutil_set(&sm->fsname, fsname);
	strutil_set(&sm->options, options);

	return sm;
}

struct system_mount *
system_mount_hold(struct system_mount *sm)
{
	if (sm != NULL) {
		if (!sm->refcount)
			log_fatal("%s: refcount == 0", __func__);
		sm->refcount += 1;
	}
	return sm;
}

void
system_mount_release(struct system_mount *sm)
{
	if (!sm->refcount)
		log_fatal("%s: refcount == 0", __func__);

	if (--(sm->refcount))
		return;

	strutil_drop(&sm->fstype);
	strutil_drop(&sm->fsname);
	strutil_drop(&sm->options);
	strutil_array_destroy(&sm->overlay_dirs);
	free(sm);
}

static bool
system_mount_tree_maybe_add_transparent(struct fstree *fstree, const fsutil_mount_cursor_t *cursor)
{
	struct fstree_node *node;
	int dtype;

	if (!strcmp(cursor->mountpoint, "/"))
		return true;

	if (cursor->fstype == NULL) {
		trace("system mount %s has null fstype", cursor->mountpoint);
		return false;
	}

	/* For the time being, ignore autofs mounts */
	if (!strcmp(cursor->fstype, "autofs"))
		return true;

	dtype = fsutil_get_dtype(cursor->mountpoint);

	if (strcmp(cursor->fstype, "overlay") || BIND_SYSTEM_OVERLAYS) {
		node = fstree_add_export(fstree, cursor->mountpoint, WORMHOLE_EXPORT_TRANSPARENT, dtype, NULL, 0);
	} else {
		node = fstree_add_export(fstree, cursor->mountpoint, WORMHOLE_EXPORT_STACKED, dtype, NULL, 0);
		if (node && cursor->overlay.dirs->count) {
			struct wormhole_layer *l;
			unsigned int j;

			if (cursor->overlay.dirs->count == 0) {
				log_error("system mount %s is an overlay, but we didn't detect any layers",
						cursor->mountpoint);
				return false;
			}

			l = wormhole_layer_new("system-layer", NULL, 0);

			for (j = 0; j < cursor->overlay.dirs->count; ++j) {
				const char *overlay_path = cursor->overlay.dirs->data[j];

				mount_config_array_add(&l->mounts, overlay_path, DT_DIR,
						MOUNT_ORIGIN_LAYER, MOUNT_MODE_OVERLAY);
			}

			wormhole_layer_array_append(&node->attached_layers, l);
			node->mount_ops = &mount_ops_overlay;
			return true;
		}
	}

	if (node == NULL) {
		log_error("failed to add node for system mount %s\n", cursor->mountpoint);
		return false;
	}

	if (node->system) {
		/* It's a setup problem for the system, but not a problem for us as we just bind mount
		 * what's there. */
		log_warning("%s: duplicate system mount (%s and %s)", cursor->mountpoint, node->system->fstype, cursor->fstype);
		return false;
	}

	node->system = system_mount_new(cursor->fstype, cursor->fsname, cursor->options);
	node->mount_ops = &mount_ops_bind;

	return true;
}

static struct fstree *
system_mount_tree_discover_transparent(void)
{
	fsutil_mount_iterator_t *it;
	fsutil_mount_cursor_t cursor;
	struct fstree *fstree;

	if (!(it = fsutil_mount_iterator_create(NULL, FSUTIL_MTAB_ITERATOR, NULL)))
		return NULL;

	fstree = fstree_new(NULL);

	while (fsutil_mount_iterator_next(it, &cursor))
		system_mount_tree_maybe_add_transparent(fstree, &cursor);

	fsutil_mount_iterator_free(it);

	fstree->root->export_type = WORMHOLE_EXPORT_ROOT;

	fstree_hide_pattern(fstree, "/tmp/*");
	fstree_hide_pattern(fstree, "/usr");
	fstree_hide_pattern(fstree, "/lib");
	fstree_hide_pattern(fstree, "/lib64");
	fstree_hide_pattern(fstree, "/bin");
	fstree_hide_pattern(fstree, "/sbin");
	fstree_hide_pattern(fstree, "/boot");
	fstree_hide_pattern(fstree, "/.snapshots");
	fstree_hide_pattern(fstree, "/var/lib/overlay");

	return fstree;
}

static bool
mount_farm_apply_layer(struct mount_farm *farm, struct wormhole_layer *layer)
{
	return wormhole_layer_build_mount_farm(layer, farm);
}

static bool
mount_farm_discover_system_mounts_transparent(struct mount_farm *farm)
{
	struct fstree *fstree = NULL;
	struct fstree_iter *it;
	struct fstree_node *node;
	bool okay = false;

	trace("Discovering system mounts");

	if (!(fstree = system_mount_tree_discover_transparent())) {
		log_error("Mount state discovery failed\n");
		return false;
	}

	it = fstree_iterator_new(fstree, false);
	while ((node = fstree_iterator_next(it)) != NULL) {
		struct fstree_node *new_mount;

		/* Just an internal tree node, not a mount */
		if (node->export_type == WORMHOLE_EXPORT_ROOT
		 || node->export_type == WORMHOLE_EXPORT_NONE)
			continue;

		new_mount = fstree_add_export(farm->tree, node->relative_path, node->export_type, node->dtype, NULL, FSTREE_QUIET);
		if (new_mount == NULL) {
			trace("overriding system mount for %s (%s) - replaced by platform", node->relative_path,
					node->system? node->system->fstype : "unknown fstype");
			continue;
		}

		trace("created new system mount for %s (%s)", node->relative_path, fstree_node_fstype(node));
		if (node->export_type != WORMHOLE_EXPORT_HIDE) {
			fstree_node_set_fstype(new_mount, node->mount_ops, farm);
			new_mount->system = system_mount_hold(node->system);
		}
	}

	okay = true;

	if (!okay)
		log_error("System mount discovery failed");

	fstree_iterator_free(it);
	fstree_free(fstree);
	return okay;
}

static bool
mount_farm_apply_quirks(struct mount_farm *farm)
{
	struct fstree_node *node;

	/* In some configurations, /dev will not be a devfs but just a regular directory
	 * with some static files in it. Catch this case. */
	if (!(node = mount_farm_add_transparent(farm, "/dev", DT_DIR, NULL)))
		return false;

	if (node->mount_ops == NULL)
		fstree_node_set_fstype(node, &mount_ops_bind, farm);

	if (!mount_farm_has_mount_for(farm, "/tmp")) {
		if (!(node = mount_farm_add_transparent(farm, "/tmp", DT_DIR, NULL)))
			return false;

		fstree_node_set_fstype(node, &mount_ops_tmpfs, farm);
	}

	if (tracing_level > 0) {
		trace("Assembled tree:");
		fstree_print(farm->tree);
		trace("---");
	}

	return true;
}

static bool
mount_farm_fill_holes(struct mount_farm *farm)
{
	struct fstree_iter *it;
	struct fstree_node *node;
	bool okay = true;

	trace("Completing system mounts");
	it = fstree_iterator_new(farm->tree, false);
	while (okay && (node = fstree_iterator_next(it)) != NULL) {
		/* Just an internal tree node, not a mount */
		if (node->export_type == WORMHOLE_EXPORT_ROOT) {
			/* It's a static directory at the tree root. Make sure it
			 * exists. */
			okay = mount_farm_add_missing_children(farm, node->relative_path);
			continue;
		}
	}

	fstree_iterator_free(it);
	return true;
}


bool
mount_farm_discover(struct mount_farm *farm, struct wormhole_layer_array *layers)
{
	bool okay = false;
	unsigned int i;

	trace("Applying layers");
	for (i = 0; i < layers->count; ++i) {
		if (!mount_farm_apply_layer(farm, layers->data[i]))
			goto out;
	}

	if (mount_farm_discover_system_mounts_transparent(farm)
	 && mount_farm_apply_quirks(farm)
	 && mount_farm_percolate(farm)
	 && mount_farm_fill_holes(farm)) {
		okay = true;
	}

out:
	return okay;
}

static int
run_the_command(struct wormhole_context *ctx)
{
	int status;

	trace("Running command:");
	if (!procutil_command_run(&ctx->command, &status)) {
		ctx->exit_status = 12;
	} else
	if (!procutil_get_exit_status(status, &ctx->exit_status)) {
		log_error("Command %s %s", ctx->command.argv[0], procutil_child_status_describe(status));
		ctx->exit_status = 13;
	} else {
		trace("Command exited with status %d\n", ctx->exit_status);
	}

	return ctx->exit_status;
}

bool
wormhole_layer_patch_rpmdb(struct wormhole_layer *layer, const char *rpmdb_orig, const char *image_root)
{
	char cmdbuf[1024];

	snprintf(cmdbuf, sizeof(cmdbuf),
			"rpmhack --patch-path '%s' patch %s",
			layer->rpmdb_path, image_root);
	trace("Executing %s", cmdbuf);

	if (system(cmdbuf) != 0) {
		log_error("Failed to patch RPM database for layer %s", layer->name);
		return false;
	}

	return true;
}

bool
wormhole_layer_diff_rpmdb(struct wormhole_layer *layer, const char *rpmdb_orig, const char *new_root)
{
	char cmdbuf[1024];

	snprintf(cmdbuf, sizeof(cmdbuf),
			"rpmhack --patch-path '%s' diff %s",
			layer->rpmdb_path, new_root);
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
	strutil_drop(&ctx->working_directory);
	strutil_drop(&ctx->workspace);
	strutil_drop(&ctx->build.target);
	strutil_drop(&ctx->build.root);
	strutil_drop(&ctx->build.bindir);
	strutil_drop(&ctx->boot.device);
	strutil_drop(&ctx->boot.fstype);
	strutil_drop(&ctx->boot.options);
	strutil_array_destroy(&ctx->build.purge_directories);

	if (ctx->farm) {
		mount_farm_free(ctx->farm);
		ctx->farm = NULL;
	}

	strutil_array_destroy(&ctx->layer_names);
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

	/* The default is to map the caller's uid/gid to 0 inside the new user namespace */
	ctx->map_caller_to_root = true;

	/* The default for building new layers is to auto-discover new entry points. */
	ctx->auto_entry_points = true;

	ctx->working_directory = get_current_dir_name();

	fsutil_tempdir_init(&ctx->temp);
	if (!(workspace = fsutil_tempdir_path(&ctx->temp))) {
		log_error("Unable to create temp space for wormhole\n");
		goto failed;
	}

	strutil_set(&ctx->workspace, workspace);
	pathutil_concat2(&ctx->image_path, workspace, "images");

	if (getuid() == 0)
		ctx->use_privileged_namespace = true;

	if (!(ctx->farm = mount_farm_new(workspace)))
		goto failed;

	return ctx;

failed:
	wormhole_context_free(ctx);
	return NULL;
}

/*
 * Set up the wormhole context for a specific purpose
 */
static inline void
wormhole_context_set_purpose(struct wormhole_context *ctx, unsigned int purpose)
{
	if (ctx->purpose != PURPOSE_NONE && ctx->purpose != purpose)
		log_fatal("Conflicting purposes for this wormhole\n");

	ctx->purpose = purpose;
}

void
wormhole_context_set_build(struct wormhole_context *ctx, const char *name, int type)
{
	wormhole_context_set_purpose(ctx, PURPOSE_BUILD);
	strutil_set(&ctx->build.target, name);
	ctx->build.target_type = type;
}

static void
wormhole_context_set_build_defaults(struct wormhole_context *ctx)
{
	/* In order for unprivileged user builds to work properly, we need to "copy up" at least
	 * all the directory inodes, so that they have the correct owner. */
	if (ctx->build.target_type == LAYER_TYPE_USER && getuid() != 0) {
		ctx->build.fudge_layer_dir_permissions = true;
	}

	/* Set the default build root */
	if (ctx->build.root == NULL) {
		ctx->build.root = wormhole_layer_make_path(ctx->build.target, ctx->build.target_type);
		if (ctx->build.root == NULL)
			log_fatal("Unable to determine layer path for build target %s", ctx->build.target);
	}

	if (fsutil_exists(ctx->build.root)) {
		if (!ctx->force)
			log_fatal("%s already exists, timidly refusing to proceed", ctx->build.root);

		/* FIXME: we should probably build the new layer in a .tmp location and then
		 * move it into place. */
		if (!fsutil_remove_recursively(ctx->build.root))
			log_fatal("failed to remove previous build of %s (located in %s)",
					ctx->build.target, ctx->build.root);
	}

	/* On transactional systems, where /usr is readonly, we won't be able to
	 * create system and site layers. Catch this early on. */
	if (!fsutil_makedirs(ctx->build.root, 0755))
		log_fatal("Unable to initialize build root %s: %m", ctx->build.root);

	if (ctx->build.bindir == NULL && ctx->build.target_type == LAYER_TYPE_USER) {
		char *bindir = pathutil_expand(WORMHOLE_USER_BIN_DIR, true);

		if (bindir == NULL) {
			/* nothing */
		} else
		if (bindir && fsutil_isdir(bindir)) {
			ctx->build.bindir = bindir;
		} else {
			strutil_drop(&bindir);
		}
	}
}

void
wormhole_context_set_boot(struct wormhole_context *ctx, const char *name)
{
	char *copy = strdup(name);
	char *options;

	wormhole_context_set_purpose(ctx, PURPOSE_BOOT);

	if ((options = strchr(copy, ';')) != NULL)
		*options++ = '\0';

	strutil_set(&ctx->boot.device, copy);
	strutil_set(&ctx->boot.options, options);
	strutil_drop(&copy);
}

static bool
wormhole_context_resolve_layers(struct wormhole_context *ctx, bool remount_layers)
{
	const char *remount_image_base = NULL;

	if (remount_layers)
		remount_image_base = ctx->image_path;
	return wormhole_layers_resolve(&ctx->layers, &ctx->layer_names, remount_image_base);
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
	if (ctx->purpose == PURPOSE_BOOT) {
		if (!wormhole_create_init_namespace())
			return false;
	} else
	if (ctx->use_privileged_namespace) {
		if (!wormhole_create_namespace())
			return false;
	} else {
		if (!wormhole_create_user_namespace(ctx->map_caller_to_root))
			return false;
	}

	if (!fsutil_make_fs_private("/", ctx->running_inside_chroot))
		return false;

	if (!fsutil_tempdir_mount(&ctx->temp))
		return false;

	return mount_farm_create_workspace(ctx->farm);
}

static bool
wormhole_context_mount_tree(struct wormhole_context *ctx)
{
	struct mount_farm *farm = ctx->farm;

	if (tracing_level > 2) {
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
prepare_tree_for_building(struct wormhole_context *ctx, bool remount_layers)
{
	struct mount_farm *farm = ctx->farm;

	trace("%s()", __func__);
	assert(ctx->build.root);

	if (!mount_farm_set_upper_base(farm, ctx->build.root))
		return false;

	if (!wormhole_context_resolve_layers(ctx, remount_layers))
		return false;

	if (!mount_farm_discover(ctx->farm, &ctx->layers))
		return false;

	/* In order for unprivileged user builds to work properly, we need to "copy up" at least
	 * all the directory inodes, so that they have the correct owner.
	 * On the flip side, if we just did this mindlessly, we would end up with lots of useless
	 * directories in the newly created image tree. To avoid that record the directories we
	 * copied up and try to prune all the empty ones when done.
	 */
	if (ctx->build.fudge_layer_dir_permissions) {
		unsigned int i;

		trace("Fudging directory permissions for layers");
		for (i = 0; i < ctx->layers.count; ++i) {
			struct wormhole_layer *layer = ctx->layers.data[i];

			wormhole_layer_copyup_directories(layer, ctx->farm->upper_base, &ctx->build.purge_directories);
		}

		/* No need to do this twice */
		ctx->build.fudge_layer_dir_permissions = false;
	}

	return true;
}

static bool
prepare_tree_for_use(struct wormhole_context *ctx)
{
	if (!wormhole_context_resolve_layers(ctx, true))
		return false;

	if (!mount_farm_discover(ctx->farm, &ctx->layers))
		return false;

	return true;
}

static bool
wormhole_context_switch_root(struct wormhole_context *ctx)
{
	struct mount_farm *farm = ctx->farm;

	if (ctx->running_inside_chroot) {
		/* Not optimal. Any mounts will propagate, and will be
		 * visible even outside the chroot environment :-( */
		trace2("Changing root to %s", farm->chroot);
		chdir(farm->chroot);
		if (chroot(farm->chroot) < 0) {
			perror("chroot");
			return 1;
		}
	} else {
		/* bind mount the chroot directory to /mnt, then clean up the temp dir. */
		if (!fsutil_mount_bind(farm->chroot, "/mnt", true))
			return 1;

		fsutil_tempdir_unmount(&ctx->temp);

		chdir("/mnt");
		if (chroot("/mnt") < 0) {
			perror("chroot");
			return 1;
		}
	}

	if (ctx->map_caller_to_root) {
		if (setgid(0) < 0)
			log_fatal("Failed to setgid(0): %m\n");
		if (setuid(0) < 0)
			log_fatal("Failed to setuid(0): %m\n");
	}

	return true;
}

bool
wormhole_context_perform_in_container(struct wormhole_context *ctx, int (*fn)(struct wormhole_context *), bool nofork)
{
	int exit_status;
	int status;

	if (nofork) {
		status = PROCUTIL_CHILD; /* just pretend we forked */
	} else {
		status = procutil_fork_and_wait(&ctx->exit_status);
	}

	if (status == PROCUTIL_CHILD) {
		/* In case people run bash */
		setenv("PS1", "wormhole> ", true);
		trace("%s: executing subprocess callback %p", __func__, fn);
		exit_status = fn(ctx);
		trace("%s: subprocess going to terminate normally, exit status = %d", __func__, exit_status);
		exit(exit_status);
	}

	if (status == PROCUTIL_CRASHED) {
		log_error("Container sub-process failed");
		return false;
	}

	if (ctx->exit_status) {
		log_error("Container sub-process exited with status %d", ctx->exit_status);
		return false;
	}

	/* In case we're running in a chroot environment (such as a local osc build)
	 * try to play nice and clean up the stuff we mounted. */
	if (ctx->running_inside_chroot) {
		trace("Trying to unmount the mount staging dir");
		__fsutil_tempdir_unmount(&ctx->temp);
	}

	trace("Container sub-process exited with status %d", ctx->exit_status);
	return true;
}

static bool
ostree_attach(struct fstree *ostree, const char *system_path)
{
	const char *image_path = fstree_get_full_path(ostree, system_path);

	// trace("Attaching %s as %s", system_path, image_path);
	if (!fsutil_makedirs(image_path, 0755))
		return false;
	return fsutil_mount_bind(system_path, image_path, true);
}

static bool
ostree_attach_readonly(struct fstree *ostree, const char *system_path)
{
	const char *image_path = fstree_get_full_path(ostree, system_path);

	// trace("Attaching %s as %s (readonly)", system_path, image_path);
	if (!fsutil_makedirs(image_path, 0755))
		return false;

	/* Attaching a system dir read-only can be achieved via an overlay with
	 * no upperdir */
	return fsutil_mount_overlay(system_path, NULL, NULL, image_path);
}

static bool
ostree_attach_tmpfs(struct fstree *ostree, const char *system_path)
{
	const char *image_path = fstree_get_full_path(ostree, system_path);

	// trace("Attaching tmpfs at %s", image_path);
	if (!fsutil_makedirs(image_path, 0755))
		return false;
	return fsutil_mount_tmpfs(image_path);
}

static int
__perform_boot(struct wormhole_context *ctx)
{
	static const char *default_fstypes[] = {
		"btrfs", "ext4", "xfs", NULL,
	};
	const char *root_dir;
	struct fstree *ostree;

	ctx->exit_status = 100;

	if (!wormhole_context_detach(ctx))
		goto out;

#if 0
	/* make sure there's a tmpfs at /tmp */
	if (!fsutil_mount_tmpfs("/tmp"))
		goto out;
#endif

	if (!fsutil_makedirs("/tmp/root", 0755))
		goto out;

	ctx->farm = mount_farm_new("/tmp/unused");
	if (fsutil_isdir(ctx->boot.device)) {
		if (ctx->boot.fstype)
			log_warning("Ignoring fstype \"%s\" while booting from directory %s", ctx->boot.fstype, ctx->boot.device);
		root_dir = ctx->boot.device;
	} else
	if (ctx->boot.fstype) {
		if (mount(ctx->boot.device, "/tmp/root", ctx->boot.fstype, 0, ctx->boot.options) < 0) {
			log_error("Cannot mount %s file system on %s: %m", ctx->boot.fstype, ctx->boot.device);
			goto out;
		}
		root_dir = "/tmp/root";
	} else {
		const char **next, *fstype;

		for (next = default_fstypes; (fstype = *next++) != NULL; ) {
			if (mount(ctx->boot.device, "/tmp/root", fstype, 0, ctx->boot.options) >= 0) {
				trace("Successfully mounted %s using %s", ctx->boot.device, fstype);
				root_dir = "/tmp/root";
				break;
			}

			trace("Failed to mount %s file system on %s: %m", fstype, ctx->boot.device);
		}
	}

	if (root_dir == NULL) {
		log_error("No root file system found");
		goto out;
	}

	ostree = fstree_new(root_dir);
	if (!ostree_attach(ostree, "/dev")
	 || !ostree_attach(ostree, "/sys")
	 || !ostree_attach_tmpfs(ostree, "/tmp")
	 || !ostree_attach_tmpfs(ostree, "/run")
	 || !ostree_attach_readonly(ostree, "/run/udev"))
		goto out;

	strutil_set(&ctx->farm->chroot, root_dir);
	if (!wormhole_context_switch_root(ctx))
		goto out;

	/* Do not mount a procfs here, but do it after fork() so that we see
	 * the pids of the new namespace */
	ctx->command.procfs_mountpoint = "/proc";

	/* FIXME: there may be more file systems that need to be mounted
	 * between fork and exec, e.g. devpts */

	if (ctx->command.argv == NULL) {
		char *argv_init[] = {
			"/usr/lib/systemd/systemd",
			"--switched-root",
			"--system",
			"--log-level", "debug",
			"--log-target", "console",
			NULL
		};
		procutil_command_init(&ctx->command, argv_init);
	}

	return run_the_command(ctx);

out:
	return ctx->exit_status;
}

static bool
prune_new_image(struct wormhole_context *ctx)
{
	char *image_root = NULL;
	struct fstree_iter *it;
	struct fstree_node *node;

	if (!prepare_tree_for_building(ctx, false))
		return false;

	pathutil_concat2(&image_root, ctx->build.root, "image");
	trace("Pruning image tree:");

	/* First step: if we did a copy-up of directories, try to purge these. */
	{
		struct strutil_array *dirs = &ctx->build.purge_directories;
		unsigned int i;

		for (i = dirs->count; i--; )
			(void) rmdir(dirs->data[i]);
	}


	it = fstree_iterator_new(ctx->farm->tree, true);
	while ((node = fstree_iterator_next(it)) != NULL) {
		const char *image_path = __pathutil_concat2(image_root, node->relative_path);
		int dtype;

		/* Don't try to remove $build_root/image */
		if (node->parent == NULL)
			break;

		if (node->export_type != WORMHOLE_EXPORT_STACKED)
			continue;

		if ((dtype = fsutil_get_dtype(image_path)) < 0)
			continue;

		if (dtype == DT_DIR)
			(void) rmdir(image_path);
		else
			(void) unlink(image_path);

		if (fsutil_exists(image_path)) {
			trace("  Has changes: %s", image_path);
		} else {
			trace2("  No changes to %s", image_path);
		}
	}

	fstree_iterator_free(it);
	free(image_root);

	trace("Removing work tree at %s/work", ctx->build.root);
	fsutil_remove_recursively(__pathutil_concat2(ctx->build.root, "work"));
	return true;
}

static int
__perform_build(struct wormhole_context *ctx)
{
	ctx->exit_status = 100;

	if (!wormhole_context_detach(ctx))
		goto out;

	if (!prepare_tree_for_building(ctx, true)
	 || !wormhole_context_mount_tree(ctx))
		goto out;

	if (ctx->manage_rpmdb && ctx->layers.count) {
		const char *root_path = ctx->farm->chroot;
		const char *rpmdb_orig = RPMDB_PATH;
		unsigned int i;

		trace("Building RPM database");
		for (i = 0; i < ctx->layers.count; ++i) {
			struct wormhole_layer *layer = ctx->layers.data[i];

			if (!wormhole_layer_patch_rpmdb(layer, rpmdb_orig, root_path))
				goto out;
		}
	}

	if (!wormhole_context_switch_root(ctx))
		goto out;

	if (run_the_command(ctx) != 0)
		goto out;

out:
	return ctx->exit_status;
}

static bool
record_modified_mounts_to_layer(struct wormhole_context *ctx, struct wormhole_layer *new_layer)
{
	struct mount_farm *farm = ctx->farm;
	char *image_root = NULL;
	unsigned int i;

	assert(ctx->build.root);

	if (!mount_farm_set_upper_base(farm, ctx->build.root))
		return false;

	if (!wormhole_context_resolve_layers(ctx, true))
		return false;

	trace("Applying layers");
	pathutil_concat2(&image_root, ctx->build.root, "image");
	for (i = 0; i < ctx->layers.count; ++i) {
		struct wormhole_layer *layer = ctx->layers.data[i];
		unsigned int j;

		for (j = 0; j < layer->mounts.count; ++j) {
			struct mount_config *mnt = layer->mounts.data[j];
			const char *image_dir_path;

			if (mnt->origin != MOUNT_ORIGIN_LAYER)
				continue;

			image_dir_path = __pathutil_concat2(image_root, mnt->path);
			if (fsutil_exists(image_dir_path)) {
				if (!mount_config_array_append(&new_layer->mounts, mnt)) {
					log_error("Cannot add %s to layer's stacked mounts", mnt->path);
					return false;
				}
				trace("  %s: add to stacked mounts", mnt->path);
			}
		}
	}

	free(image_root);
	return true;
}

/*
 * Discover applications in PATH directories
 */
static void
__discover_entry_points(struct wormhole_layer *layer, const char *bindir)
{
	char pathbuf[PATH_MAX];
	DIR *dir;
	struct dirent *d;

	snprintf(pathbuf, sizeof(pathbuf), "%s%s", layer->image_path, bindir);
	trace2("Searching %s for applications", pathbuf);

	if (!(dir = opendir(pathbuf))) {
		trace3("%s: %m", pathbuf);
		return;
	}

	while ((d = readdir(dir)) != NULL) {
		int dtype = d->d_type;

		/* awscli creates absolute symlinks /usr/local/bin -> /usr/local/aws-cli/v2/current/bin/aws */
		if (dtype != DT_REG && dtype != DT_LNK)
			continue;

		/* FIXME: should we check for +x permissions? */

		snprintf(pathbuf, sizeof(pathbuf), "%s/%s", bindir, d->d_name);
		strutil_array_append(&layer->entry_points, pathbuf);
	}

	closedir(dir);
}

void
discover_entry_points(struct wormhole_layer *layer)
{
	const char *PATH[] = {
		"/bin",
		"/sbin",
		"/usr/bin",
		"/usr/local/bin",
		"/opt/bin",
		NULL
	};
	const char **pos, *bindir;
	unsigned int last, count;

	last = layer->entry_points.count;
	for (pos = PATH; (bindir = *pos++) != NULL; )
		__discover_entry_points(layer, bindir);

	count = layer->entry_points.count - last;
	if (count == 0) {
		trace("No entry points discovered");
	} else {
		trace("Discovered %u entry points", count);
		while (last < layer->entry_points.count) {
			const char *path = layer->entry_points.data[last++];

			trace("  entry point %s", path);
		}
	}
}

static void
do_build(struct wormhole_context *ctx)
{
	struct wormhole_layer *layer;
	unsigned int i;

	/* Set the build root etc. */
	wormhole_context_set_build_defaults(ctx);

#if 0
	if (!ctx->use_privileged_namespace) {
		log_error("Currently, you must be root to build wormhole layers\n");
		return;
	}
#endif

	trace("Performing build stage");
	if (!wormhole_context_perform_in_container(ctx, __perform_build, false))
		return;

	/* Now post-process the build. */
	trace("Post-process build result");

	if (!prune_new_image(ctx))
		return;

	layer = wormhole_layer_new(ctx->build.target, ctx->build.root, 0);
	for (i = 0; i < ctx->layer_names.count; ++i) {
		const char *name = ctx->layer_names.data[i];

		strutil_array_append(&layer->used, name);
	}

	record_modified_mounts_to_layer(ctx, layer);

	if (ctx->manage_rpmdb) {
		const char *rpmdb_orig = RPMDB_PATH;

		if (ctx->layers.count)
			rpmdb_orig = ctx->layers.data[ctx->layers.count - 1]->rpmdb_path;
		if (!wormhole_layer_diff_rpmdb(layer, rpmdb_orig, ctx->farm->chroot)) {
			log_error("Failed to create RPM database diff");
			return;
		}
	}

	if (!wormhole_layer_save_config(layer)) {
		log_error("Unable to write configuration for new layer");
		return;
	}

	if (ctx->auto_entry_points) {
		discover_entry_points(layer);

		if (ctx->build.target_type == LAYER_TYPE_USER)
			wormhole_layer_create_default_wrapper_symlinks(layer);
	}

	if (!wormhole_layer_write_wrappers(layer, ctx->build.bindir)) {
		log_error("Unable to create wrapper scripts for new layer");
		return;
	}

	log_info("New image can be found in %s", ctx->build.root);
	ctx->exit_status = 0;
}

static void
do_boot(struct wormhole_context *ctx)
{
	if (!ctx->use_privileged_namespace) {
		log_error("Currently, you must be root to build wormhole layers\n");
		return;
	}

	if (ctx->layer_names.count) {
		log_error("You cannot specify layers while using the --boot option");
		return;
	}

	trace("Booting OS image at %s", ctx->boot.device);
	if (!wormhole_context_perform_in_container(ctx, __perform_boot, true))
		return;

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

	return run_the_command(ctx);

out:
	return 42;
}

static void
do_run(struct wormhole_context *ctx)
{
	if (!wormhole_context_perform_in_container(ctx, __run_container, false))
		return;

	ctx->exit_status = 0;
}

enum {
	OPT_BUILD_USER_LAYER = 256,
	OPT_BUILD_SITE_LAYER,
	OPT_BUILD_SYSTEM_LAYER,
	OPT_BOOT,
	OPT_RUNAS_ROOT,
	OPT_RUNAS_USER,
	OPT_AUTO_ENTRY_POINTS,
	OPT_NO_AUTO_ENTRY_POINTS,
	OPT_INSTALL_BINDIR,
	OPT_RPMDB,
	OPT_LOGFILE,
};

static struct option	long_options[] = {
	{ "debug",	no_argument,		NULL,	'd'		},
	{ "build",	required_argument,	NULL,	OPT_BUILD_USER_LAYER },
	{ "build-user-layer",
			required_argument,	NULL,	OPT_BUILD_USER_LAYER },
	{ "build-site-layer",
			required_argument,	NULL,	OPT_BUILD_SITE_LAYER },
	{ "build-system-layer",
			required_argument,	NULL,	OPT_BUILD_SYSTEM_LAYER },
	{ "boot",	required_argument,	NULL,	OPT_BOOT	},
	{ "buildroot",	required_argument,	NULL,	'R'		},
	{ "use",	required_argument,	NULL,	'u'		},
	{ "layer",	required_argument,	NULL,	'L'		},
	{ "force",	no_argument,		NULL,	'f'		},
	{ "rpmdb",	no_argument,		NULL,	OPT_RPMDB	},
	{ "run-as-root",no_argument,		NULL,	OPT_RUNAS_ROOT	},
	{ "run-as-user",no_argument,		NULL,	OPT_RUNAS_USER	},
	{ "auto-entry-points",
			no_argument,		NULL,	OPT_AUTO_ENTRY_POINTS },
	{ "no-auto-entry-points",
			no_argument,		NULL,	OPT_NO_AUTO_ENTRY_POINTS },
	{ "install-bindir",
			required_argument,	NULL,	OPT_INSTALL_BINDIR },
	{ "logfile",	required_argument,	NULL,	OPT_LOGFILE	},

	{ NULL },
};

int
main(int argc, char **argv)
{
	struct wormhole_context *ctx;
	int exit_status = 1;
	int c;

	ctx = wormhole_context_new();

	while ((c = getopt_long(argc, argv, "B:dfL:R:u:", long_options, NULL)) != EOF) {
		switch (c) {
		case 'B':
		case OPT_BUILD_USER_LAYER:
			wormhole_context_set_build(ctx, optarg, LAYER_TYPE_USER);
			break;

		case OPT_BUILD_SITE_LAYER:
			wormhole_context_set_build(ctx, optarg, LAYER_TYPE_SITE);
			break;

		case OPT_BUILD_SYSTEM_LAYER:
			wormhole_context_set_build(ctx, optarg, LAYER_TYPE_SYSTEM);
			break;

		case OPT_BOOT:
			wormhole_context_set_boot(ctx, optarg);
			break;

		case 'd':
			tracing_increment_level();
			break;

		case 'f':
			ctx->force = true;
			break;

		case 'R':
			strutil_set(&ctx->build.root, optarg);
			break;

		case 'L':
		case 'u':
			strutil_array_append(&ctx->layer_names, optarg);
			break;

		case OPT_RPMDB:
			ctx->manage_rpmdb = true;
			break;

		case OPT_RUNAS_ROOT:
			ctx->map_caller_to_root = true;
			break;

		case OPT_RUNAS_USER:
			ctx->map_caller_to_root = false;
			break;

		case OPT_AUTO_ENTRY_POINTS:
			ctx->auto_entry_points = true;
			break;

		case OPT_NO_AUTO_ENTRY_POINTS:
			ctx->auto_entry_points = false;
			break;

		case OPT_INSTALL_BINDIR:
			strutil_set(&ctx->build.bindir, optarg);
			break;

		case OPT_LOGFILE:
			set_logfile(optarg);
			break;

		default:
			log_error("Unknown option\n");
			return 1;
		}
	}

	trace("debug level set to %u\n", tracing_level);

	if (optind < argc) {
		wormhole_context_set_command(ctx, argv + optind);

		/* Set the working directory so that relative path name arguments
		 * continue to work. */
		ctx->command.working_directory = ctx->working_directory;
	} else
	if (ctx->purpose == PURPOSE_BUILD || ctx->purpose == PURPOSE_USE)
		log_fatal("Missing command to be executed\n");

	if (!fsutil_dir_is_mountpoint("/")) {
		log_warning("Running inside what looks like a chroot environment.");
		ctx->running_inside_chroot = true;
	}

	wormhole_layer_set_default_search_path();

	switch (ctx->purpose) {
	case PURPOSE_BUILD:
		do_build(ctx);
		break;

	case PURPOSE_BOOT:
		do_boot(ctx);
		break;

	case PURPOSE_NONE:
		wormhole_context_set_purpose(ctx, PURPOSE_USE);
		/* fallthru */

	case PURPOSE_USE:
		do_run(ctx);
		break;

	default:
		log_error("Unsupported purpose %u", ctx->purpose);
		return 1;
	}

	exit_status = ctx->exit_status;
	wormhole_context_free(ctx);

	return exit_status;
}
