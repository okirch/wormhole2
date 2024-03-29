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

static bool
system_mount_tree_discover_boot(struct fstree *fstree)
{
	const char *root_dir = fstree->root_location->path;
	fsutil_mount_iterator_t *it;
	fsutil_mount_cursor_t cursor;

	if (root_dir == NULL) {
		log_error("%s: refusing to operate on /", __func__);
		return false;
	}

	if (!(it = fsutil_mount_iterator_create(root_dir, FSUTIL_FSTAB_ITERATOR, NULL)))
		return false;

	while (fsutil_mount_iterator_next(it, &cursor)) {
		fsutil_mount_detail_t *md = cursor.detail;
		fstree_node_t *node;

		if (fsutil_mount_options_contain(md->options, "noauto"))
			continue;

		if (!strcmp(md->fstype, "swap"))
			continue;

		if (!strcmp(md->fstype, "nfs")) {
			log_warning("Ignoring NFS file system at %s for now", cursor.mountpoint);
			continue;
		}

		node = fstree_add_export(fstree, cursor.mountpoint, WORMHOLE_EXPORT_MOUNTIT, DT_UNKNOWN, NULL, 0);
		if (node == NULL)
			return false;

		strutil_set(&node->mount.mount_point, node->relative_path);
		node->mount.detail = fsutil_mount_detail_hold(md);

		if (!strncmp(md->fsname, "UUID=", 5)) {
			char *real_device;

			real_device = fsutil_resolve_fsuuid(md->fsname + 5);
			if (real_device) {
				strutil_drop(&md->fsname);
				md->fsname = real_device;
				node->mount_ops = &mount_ops_direct;
			}
		}
		if (node->mount_ops == NULL)
			node->mount_ops = &mount_ops_mountcmd;
		node->export_flags |= FSTREE_NODE_F_MAYREPLACE;
	}

	fsutil_mount_iterator_free(it);

#if 1
	/* When we get here, we have already mounted the root FS */
	if (fstree->root)
		fstree_node_reset(fstree->root);
#else
	if (fstree->root == NULL || fstree->root->mount_ops == NULL) {
		log_error("%s: could not find a file system for / in %s/etc/fstab",
				__func__, root_dir);
		return false;
	}
	fstree->root->mount_ops = &mount_ops_direct;
#endif

	fstree_hide_pattern(fstree, "/tmp/*");
	fstree_hide_pattern(fstree, "/dev");
	fstree_hide_pattern(fstree, "/sys");
	fstree_hide_pattern(fstree, "/proc");
	fstree_hide_pattern(fstree, "/dev/pts");
	fstree_hide_pattern(fstree, "/run");

	return true;
}

static inline void
cannot_change_mount(struct fstree_node *node)
{
	trace("cannot change %s mount for %s (%s) - replaced by platform",
			node->mount_ops? node->mount_ops->name : "unspecific",
			node->relative_path,
			node->mount.detail? node->mount.detail->fstype : "unknown fstype");
}

static bool
mount_farm_apply_layer(struct mount_farm *farm, struct wormhole_layer *layer)
{
	return wormhole_layer_build_mount_farm(layer, farm);
}

static bool
mount_farm_merge_system_mounts(struct mount_farm *farm, struct fstree *fstree)
{
	struct fstree_iter *it;
	struct fstree_node *node;
	bool okay = false;

	node = fstree->root;

	it = fstree_iterator_new(fstree, false);
	while ((node = fstree_iterator_next(it)) != NULL) {
		struct fstree_node *new_mount;

		/* Just an internal tree node, not a mount */
		if (node->export_type == WORMHOLE_EXPORT_ROOT
		 || node->export_type == WORMHOLE_EXPORT_NONE)
		{
			trace("Skipping %s type %u", node->relative_path, node->export_type);
			continue;
		}

		new_mount = fstree_add_export(farm->tree, node->relative_path, node->export_type, node->dtype, NULL, FSTREE_QUIET);
		if (new_mount == NULL) {
			cannot_change_mount(node);
			continue;
		}

		trace("created new system mount for %s (%s)", node->relative_path, fstree_node_fstype(node));
		if (node->export_type != WORMHOLE_EXPORT_HIDE) {
			mount_ops_t *mount_ops = node->mount_ops;

			if (mount_ops == &mount_ops_overlay)
				mount_ops = farm->mount_ops.overlay;

			fstree_node_set_fstype(new_mount, mount_ops, farm);
			new_mount->mount.detail = fsutil_mount_detail_hold(node->mount.detail);

			if (node->attached_layers.count) {
				unsigned int i;

				for (i = 0; i < node->attached_layers.count; ++i) {
					struct wormhole_layer *l = node->attached_layers.data[i];

					wormhole_layer_array_append(&new_mount->attached_layers, l);
				}
			}

			new_mount->export_flags |= (node->export_flags & FSTREE_NODE_F_TRACK);
		}
	}

	okay = true;

	if (!okay)
		log_error("System mount discovery failed");

	fstree_iterator_free(it);
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
wormhole_context_define_mount_tree(struct wormhole_context *ctx)
{
	struct wormhole_layer_array *layers = &ctx->layer.array;
	struct mount_farm *farm = ctx->farm;
	struct fstree *fstree = NULL;
	bool okay = false;
	unsigned int i;

	trace("Applying layers");
	for (i = 0; i < layers->count; ++i) {
		struct wormhole_layer *layer = layers->data[i];

		if (!mount_farm_apply_layer(farm, layer))
			goto out;
	}

	trace("Discovering system mounts");
	fstree = system_mount_tree_discover(ctx->layer.base_layer_type, ctx->purpose);
	if (fstree == NULL) {
		log_error("Mount state discovery failed\n");
		goto out;
	}

	if (!mount_farm_merge_system_mounts(farm, fstree))
		goto out;

	if (farm->tree->root->export_type == WORMHOLE_EXPORT_NONE)
		farm->tree->root->export_type = WORMHOLE_EXPORT_ROOT;

	if (mount_farm_apply_quirks(farm)
	 && mount_farm_pushdown_overlays(farm)
	 && mount_farm_percolate(farm)
	 && mount_farm_fill_holes(farm)) {
		okay = true;
	}

out:
	if (fstree)
		fstree_free(fstree);
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
	strutil_array_destroy(&ctx->build.purge_directories);

	if (ctx->boot.mount_detail) {
		fsutil_mount_detail_release(ctx->boot.mount_detail);
		ctx->boot.mount_detail = NULL;
	}

	if (ctx->farm) {
		mount_farm_free(ctx->farm);
		ctx->farm = NULL;
	}

	strutil_array_destroy(&ctx->layer.names);
	wormhole_layer_array_destroy(&ctx->layer.array);

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

	/* The default for building new layers is to auto-discover new entry points. */
	ctx->auto_entry_points = true;

	/* By default, we will try to remount layer in order to shorten the path names
	 * that go into the overlay mount options. */
	ctx->remount_layers = true;

	ctx->working_directory = get_current_dir_name();

	fsutil_tempdir_init(&ctx->temp);
	if (!(workspace = fsutil_tempdir_path(&ctx->temp))) {
		log_error("Unable to create temp space for wormhole\n");
		goto failed;
	}

	strutil_set(&ctx->workspace, workspace);

	/* By default, we ask all layers to be remounted in order
	 * to shorten the path names used in overlays. This is to avoid
	 * running into the kernel's size limits on mount options. */
	pathutil_concat2(&ctx->layer.remount_image_base, workspace, "images");

	if (getuid() == 0)
		ctx->use_privileged_namespace = true;

	/* Is this the right time and place to do it?
	 * We should probably defer this until we know the purpose. */
	if (!(ctx->farm = mount_farm_new(ctx->purpose, workspace)))
		goto failed;

	return ctx;

failed:
	wormhole_context_free(ctx);
	return NULL;
}

static inline void
wormhole_context_set_flag_user(struct wormhole_context *ctx, unsigned int word)
{
	ctx->flags |= word;
	ctx->flags_set_by_user |= word;
}

static inline void
wormhole_context_clear_flag_user(struct wormhole_context *ctx, unsigned int word)
{
	ctx->flags &= ~word;
	ctx->flags_set_by_user |= word;
}

static inline void
wormhole_context_set_flag_default(struct wormhole_context *ctx, unsigned int word)
{
	if (!(ctx->flags_set_by_user & word))
		ctx->flags |= word;
}

static inline void
wormhole_context_clear_flag_default(struct wormhole_context *ctx, unsigned int word)
{
	if (!(ctx->flags_set_by_user & word))
		ctx->flags &= ~word;
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
	/* If the user hasn't requested otherwise, the default during build
	 * is to map the caller's uid/gid to 0 inside the new user namespace */
	wormhole_context_set_flag_default(ctx, WORMHOLE_F_MAP_USER_TO_ROOT);

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

	ctx->boot.mount_detail = fsutil_mount_detail_new(NULL, copy, options);
	strutil_drop(&copy);
}

static bool
wormhole_context_resolve_layers(struct wormhole_context *ctx)
{
	return wormhole_layers_resolve(&ctx->layer);
}

static bool
wormhole_context_remount_layers(struct wormhole_context *ctx)
{
	return wormhole_layers_remount(&ctx->layer);
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
		if (!wormhole_create_user_namespace(ctx->flags & WORMHOLE_F_MAP_USER_TO_ROOT))
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
define_tree_for_building(struct wormhole_context *ctx)
{
	struct mount_farm *farm = ctx->farm;

	trace("%s()", __func__);
	assert(ctx->build.root);

	if (!mount_farm_set_upper_base(farm, ctx->build.root))
		return false;

	if (!wormhole_context_resolve_layers(ctx))
		return false;

	if (!wormhole_context_define_mount_tree(ctx))
		return false;

	return true;
}

static bool
prepare_tree_for_building(struct wormhole_context *ctx)
{
	trace("%s()", __func__);
	if (ctx->remount_layers && !wormhole_context_remount_layers(ctx))
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
		for (i = 0; i < ctx->layer.array.count; ++i) {
			struct wormhole_layer *layer = ctx->layer.array.data[i];

			wormhole_layer_copyup_directories(layer, ctx->farm->upper_base, &ctx->build.purge_directories);
		}

		/* No need to do this twice */
		ctx->build.fudge_layer_dir_permissions = false;
	}

	return true;
}

static bool
define_tree_for_use(struct wormhole_context *ctx)
{
	trace("%s()", __func__);

	if (!wormhole_context_resolve_layers(ctx))
		return false;

	if (ctx->layer.base_layer_type == WORMHOLE_BASE_LAYER_HOST) {
		trace("This application is configured to use the host root directory");

		/* We're in USE mode, so just use the host root as-is */
		mount_farm_use_system_root(ctx->farm);

		/* Do not perform a chroot when switching */
		ctx->no_switch_root = true;

		/* Do not bother with trying to remount any layers */
		ctx->remount_layers = false;
	}

	if (!wormhole_context_define_mount_tree(ctx))
		return false;

	return true;
}

static bool
prepare_tree_for_use(struct wormhole_context *ctx)
{
	if (ctx->remount_layers && !wormhole_context_remount_layers(ctx))
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
	} else if (!ctx->no_switch_root) {
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

	if (ctx->flags & WORMHOLE_F_MAP_USER_TO_ROOT) {
		if (setgid(0) < 0)
			log_fatal("Failed to setgid(0): %m\n");
		if (setuid(0) < 0)
			log_fatal("Failed to setuid(0): %m\n");
	}

	if (ctx->no_selinux) {
		log_warning("Cannot disable SELinux mode - not yet implemented");
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

static bool
identify_os(const char *root_dir)
{
	bool found = false;
	FILE *fp;
	char line[128];

	fp = fopen(__pathutil_concat2(root_dir, "/etc/os-release"), "r");
	if (fp == NULL)
		return false;

	while (fgets(line, sizeof(line), fp) != NULL) {
		char *os_name, *s;

		line[strcspn(line, "\r\n")] = '\0';

		if (strncmp(line, "PRETTY_NAME=", 12))
			continue;
		os_name = line + 12;

		if (*os_name == '"') {
			++os_name;
			if ((s = strchr(os_name, '"')) != NULL)
				*s = '\0';
		}

		log_info("Found installation of %s", os_name);
		found = true;
		break;
	}

	fclose(fp);
	return found;
}

static bool
boot_run_prep_script(struct wormhole_context *ctx)
{
	char *argv[] = { ctx->boot.prep_script, NULL };
	struct procutil_command cmd;
	int status;
	bool ok = false;

	procutil_command_init(&cmd, argv);
	procutil_command_setenv(&cmd, "WORMHOLE_ROOT", ctx->farm->chroot);

	if (!procutil_command_run(&cmd, &status)) {
		log_error("Failed to run boot prep script");
		goto out;
	}

	if (!procutil_child_status_okay(status)) {
		log_error("boot prep script %s: %s", ctx->boot.prep_script,
				procutil_child_status_describe(status));
		goto out;
	}

	log_debug("boot prep script %s: succeeded", ctx->boot.prep_script);
	ok = true;

out:
	procutil_command_destroy(&cmd);
	return ok;
}

static int
__perform_boot(struct wormhole_context *ctx)
{
	static const char *default_fstypes[] = {
		"btrfs", "ext4", "xfs", NULL,
	};
	const char *root_dir;
	fsutil_mount_detail_t *md;
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

	/* do_boot() has already checked that boot.mount_detail is set and contains
	 * at least a valid fsname */
	md = ctx->boot.mount_detail;
	if (fsutil_isdir(md->fsname)) {
		if (md->fstype)
			log_warning("Ignoring fstype \"%s\" while booting from directory %s", md->fstype, md->fsname);
		root_dir = md->fsname;
	} else
	if (md->fstype) {
		if (mount(md->fsname, "/tmp/root", md->fstype, 0, md->options) < 0) {
			log_error("Cannot mount %s file system on %s: %m", md->fstype, md->fsname);
			goto out;
		}
		root_dir = "/tmp/root";
	} else {
		const char **next, *fstype;

		for (next = default_fstypes; (fstype = *next++) != NULL; ) {
			if (mount(md->fsname, "/tmp/root", fstype, 0, md->options) >= 0) {
				trace("Successfully mounted %s using %s", md->fsname, fstype);
				root_dir = "/tmp/root";
				break;
			}

			trace("Failed to mount %s file system on %s: %m", fstype, md->fsname);
		}
	}

	if (root_dir == NULL) {
		log_error("No root file system found");
		goto out;
	}

	ctx->farm = mount_farm_new(ctx->purpose, root_dir);

	if (!identify_os(root_dir)
	 || !system_mount_tree_discover_boot(ctx->farm->tree)) {
		log_error("%s does not seem to contain a valid OS installation", root_dir);
		goto out;
	}

	ostree = ctx->farm->tree;

	/* We first need to mount various file systems to allow mount(8) to work properly. */
	if (!ostree_attach(ostree, "/sys")
	 || !ostree_attach(ostree, "/dev"))
		goto out;

	if (!wormhole_context_mount_tree(ctx))
		goto out;

	if (!ostree_attach_tmpfs(ostree, "/tmp")
	 || !ostree_attach_tmpfs(ostree, "/run")
	 || !ostree_attach_readonly(ostree, "/run/udev"))
		goto out;

	if (ctx->boot.prep_script) {
		if (!boot_run_prep_script(ctx))
			goto out;
	}

	if (!wormhole_context_switch_root(ctx))
		goto out;

	/* Do not mount a procfs here, but do it after fork() so that we see
	 * the pids of the new namespace.
	 * The same applies to /dev/pts.
	 */
	procutil_command_require_virtual_fs(&ctx->command, "proc", "/proc", NULL,
			MS_NODEV | MS_NOSUID | MS_NOEXEC);
	procutil_command_require_virtual_fs(&ctx->command, "devpts", "/dev/pts",
			"gid=5,mode=620,ptmxmode=000", MS_NOSUID | MS_NOEXEC);

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

	if (!prepare_tree_for_building(ctx)
	 || !wormhole_context_mount_tree(ctx))
		goto out;

	if (ctx->manage_rpmdb && ctx->layer.array.count) {
		const char *root_path = ctx->farm->chroot;
		const char *rpmdb_orig = RPMDB_PATH;
		unsigned int i;

		trace("Building RPM database");
		for (i = 0; i < ctx->layer.array.count; ++i) {
			struct wormhole_layer *layer = ctx->layer.array.data[i];

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
	struct fstree *fstree = ctx->farm->tree;
	struct fsutil_ftw_ctx *ftw;
	struct fsutil_ftw_cursor cursor;

	if (!(ftw = fsutil_ftw_open("/", FSUTIL_FTW_NEED_STAT, new_layer->image_path)))
		return false;

	while (fsutil_ftw_next(ftw, &cursor)) {
		struct fstree_node *node;

		node = fstree_node_closest_ancestor(fstree->root, cursor.relative_path);
		if (node == NULL) {
			log_warning("Cannot identify a mount point for %s", cursor.relative_path);
			continue;
		}

		trace("%s belongs to %s%s", cursor.relative_path, node->relative_path,
				(node->export_flags & FSTREE_NODE_F_TRACK)? "" : " (ignored)");

		if (!(node->export_flags & FSTREE_NODE_F_TRACK))
			continue;

		if (!strcmp(node->relative_path, "/")) {
			const char *tld;

			/* If we track "/", and find a newly added file like /usr/bin/frobber, then
			 * insert an extra tracking node at /usr */
			if (!(tld = pathutil_toplevel_dirname(cursor.relative_path))
			 || !(node = fstree_node_lookup(fstree->root, tld, true))) {
				log_error("%s: cannot handle %s", __func__, cursor.relative_path);
				continue;
			}

			node->export_flags |= FSTREE_NODE_F_TRACK;
		}

		if (node->export_flags & FSTREE_NODE_F_MODIFIED)
			continue;

		trace("  Need to insert a transparent mount for %s", node->relative_path);
		mount_config_array_add(&new_layer->mounts, node->relative_path,
				__fsutil_get_dtype(cursor.st),
				MOUNT_ORIGIN_LAYER,
				MOUNT_MODE_OVERLAY);

		node->export_flags |= FSTREE_NODE_F_MODIFIED;
	}
	fsutil_ftw_ctx_free(ftw);
	return true;
}

static bool
prune_empty_mountpoints(struct wormhole_context *ctx, struct wormhole_layer *new_layer)
{
	struct mount_farm *farm = ctx->farm;
	struct fstree_iter *iter;
	struct fstree_node *node;

	/* it's important that we perform a depth-first traversal so that we
	 * map any modifications to the proper overlay. */
	iter = fstree_iterator_new(farm->tree, true);
	while ((node = fstree_iterator_next(iter)) != NULL) {
		/* This is somewhat lame and incomplete, in that we do not catch any dirs
		 * that were created for mounts like /proc/something */
		if (node->upper)
			fsutil_remove_empty_dir_and_parents(node->relative_path, new_layer->image_path);
	}

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

	trace("Defining mount tree");
	if (!define_tree_for_building(ctx))
		return;

	trace("Performing build stage");
	if (!wormhole_context_perform_in_container(ctx, __perform_build, false))
		return;

	/* Now post-process the build. */
	trace("Post-process build result");

	if (!prune_new_image(ctx))
		return;

	layer = wormhole_layer_new(ctx->build.target, ctx->build.root, 0);
	for (i = 0; i < ctx->layer.names.count; ++i) {
		const char *name = ctx->layer.names.data[i];

		strutil_array_append(&layer->used, name);
	}

	prune_empty_mountpoints(ctx, layer);
	record_modified_mounts_to_layer(ctx, layer);

	if (ctx->manage_rpmdb) {
		const char *rpmdb_orig = RPMDB_PATH;

		if (ctx->layer.array.count)
			rpmdb_orig = ctx->layer.array.data[ctx->layer.array.count - 1]->rpmdb_path;
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
	const char *boot_device;

	if (!ctx->use_privileged_namespace) {
		log_error("Currently, you must be root to build wormhole layers\n");
		return;
	}

	if (ctx->layer.names.count) {
		log_error("You cannot specify layers while using the --boot option");
		return;
	}

	if (ctx->boot.mount_detail == NULL
	 || (boot_device = ctx->boot.mount_detail->fsname) == NULL) {
		log_error("No boot device specified");
		return;
	}

	trace("Booting OS image at %s", boot_device);
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
	trace("Defining mount tree");
	if (!define_tree_for_use(ctx))
		return;

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
	OPT_BOOT_PREP_SCRIPT,
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
	{ "boot-prep-script",
			required_argument,	NULL,	OPT_BOOT_PREP_SCRIPT	},

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
			/* For now, turn off SELinux unconditionally */
			ctx->no_selinux = true;
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
			strutil_array_append(&ctx->layer.names, optarg);
			break;

		case OPT_RPMDB:
			ctx->manage_rpmdb = true;
			break;

		case OPT_RUNAS_ROOT:
			wormhole_context_set_flag_user(ctx, WORMHOLE_F_MAP_USER_TO_ROOT);
			break;

		case OPT_RUNAS_USER:
			wormhole_context_clear_flag_user(ctx, WORMHOLE_F_MAP_USER_TO_ROOT);
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

		case OPT_BOOT_PREP_SCRIPT:
			strutil_set(&ctx->boot.prep_script, optarg);

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
