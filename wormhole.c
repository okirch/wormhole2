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

static bool
__mount_farm_discover_callback(void *closure, const char *mount_point,
                                const char *mnt_type,
                                const char *fsname)
{
	struct fstree *fstree = closure;
	struct fstree_node *node;

	if (!strcmp(mount_point, "/"))
		return true;

	if (!strncmp(mount_point, "/tmp/", 5)) {
		trace3("Ignoring mount point %s\n", mount_point);
		return true;
	}

	node = fstree_add_export(fstree, mount_point, WORMHOLE_EXPORT_TRANSPARENT, NULL);
	if (node == NULL) {
		log_error("mount_farm_add_transparent(%s) failed\n", mount_point);
		return false;
	}

	if (node->fstype) {
		log_error("%s: duplicate mount (%s -> %s)", mount_point, node->fstype, mnt_type);
		return false;
	}
	assert(node->fstype == NULL);
	assert(node->fsname == NULL);
	node->fstype = strdup(mnt_type);
	node->fsname = strdup(fsname);
	return true;
}

static bool
mount_farm_apply_layer(struct mount_farm *farm, struct wormhole_layer *layer)
{
	return wormhole_layer_build_mount_farm(layer, farm);
}

static bool
mount_farm_discover_system_mounts(struct mount_farm *farm)
{
	struct fstree *fstree = NULL;
	struct fstree_iter *it;
	struct fstree_node *node;

	trace("Discovering system mounts");

	fstree = fstree_new(NULL);
	if (!fstree_discover(NULL, __mount_farm_discover_callback, fstree)) {
		log_error("Mount state discovery failed\n");
		return false;
	}

	it = fstree_iterator_new(fstree, false);
	while ((node = fstree_iterator_next(it)) != NULL) {
		struct fstree_node *new_mount;

		trace("  %s", node->relative_path);

		/* Just an internal tree node, not a mount */
		if (node->export_type == WORMHOLE_EXPORT_NONE)
			continue;

		if (!strncmp(node->relative_path, "/usr", 4)
		 || !strncmp(node->relative_path, "/bin", 4)
		 || !strncmp(node->relative_path, "/lib", 4)
		 || !strncmp(node->relative_path, "/lib64", 6)) {
			log_warning("Ignoring mount point %s", node->relative_path);
			continue;
		}

		new_mount = mount_farm_add_transparent(farm, node->relative_path, NULL);
		if (node->fsname && node->fsname[0] == '/' && fsutil_isblk(node->fsname)) {
			/* this is a mount of an actual block based file system */
			trace("%s is a mount of %s", node->relative_path, node->fsname);
			fstree_node_set_fstype(new_mount, "bind", farm);
		} else
		if (new_mount->fstype == NULL || !strcmp(new_mount->fstype, node->fstype)) {
			/* Most likely a virtual FS */
			fstree_node_set_fstype(new_mount, node->fstype, farm);
		}
	}

	fstree_iterator_free(it);
	fstree_free(fstree);
	return true;
}

static bool
mount_farm_apply_quirks(struct mount_farm *farm)
{
	struct fstree_node *node;

	/* In some configurations, /dev will not be a devfs but just a regular directory
	 * with some static files in it. Catch this case. */
	if (!(node = mount_farm_add_transparent(farm, "/dev", NULL)))
		return false;

	if (node->fstype == NULL)
		fstree_node_set_fstype(node, "bind", farm);

	if (!(node = mount_farm_add_transparent(farm, "/tmp", NULL)))
		return false;

	fstree_node_set_fstype(node, "tmpfs", farm);

	trace("Assembled tree:");
	fstree_print(farm->tree);
	trace("---");

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

	if (mount_farm_discover_system_mounts(farm)
	 && mount_farm_apply_quirks(farm)
	 && mount_farm_percolate(farm)
	 && mount_farm_fill_holes(farm)) {
		okay = true;
	}

out:
	return okay;
}

bool
mount_farm_assemble_for_build(struct mount_farm *farm, struct wormhole_layer_array *layers)
{
	return mount_farm_discover(farm, layers);
}

bool
mount_farm_assemble_for_run(struct mount_farm *farm, struct wormhole_layer_array *layers)
{
	return mount_farm_discover(farm, layers);
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

enum {
	PURPOSE_NONE,
	PURPOSE_BUILD,
	PURPOSE_USE,
	PURPOSE_BOOT,

	__PURPOSE_MESSING_AROUND,
};

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
	strutil_drop(&ctx->build_target);
	strutil_drop(&ctx->build_root);

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
wormhole_context_set_build(struct wormhole_context *ctx, const char *name)
{
	wormhole_context_set_purpose(ctx, PURPOSE_BUILD);
	strutil_set(&ctx->build_target, name);

	/* Set the default build root */
	if (ctx->build_root == NULL) {
		strutil_set(&ctx->build_root, fsutil_makedir2(get_current_dir_name(), "wormhole-build"));
		if (ctx->build_root == NULL)
			log_fatal("Cannot set build root to $PWD/wormhole-build");
	}
}

void
wormhole_context_set_boot(struct wormhole_context *ctx, const char *name)
{
	wormhole_context_set_purpose(ctx, PURPOSE_BOOT);
	strutil_set(&ctx->boot_device, name);
}

static bool
wormhole_context_resolve_layers(struct wormhole_context *ctx)
{
	return wormhole_layers_resolve(&ctx->layers, &ctx->layer_names, ctx->image_path);
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
		if (!wormhole_create_user_namespace(true))
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
prepare_tree_for_building(struct wormhole_context *ctx)
{
	struct mount_farm *farm = ctx->farm;

	trace("%s()", __func__);
	assert(ctx->build_root);

	if (!mount_farm_set_upper_base(farm, ctx->build_root))
		return false;

	if (!wormhole_context_resolve_layers(ctx))
		return false;

	trace("About to call mount_farm_assemble_for_build");
	if (!mount_farm_assemble_for_build(farm, &ctx->layers))
		return false;

	return true;
}

static bool
prepare_tree_for_use(struct wormhole_context *ctx)
{
	struct mount_farm *farm = ctx->farm;

	if (!wormhole_context_resolve_layers(ctx))
		return false;

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
	if (!fsutil_mount_bind("/usr", "/var/tmp/lalla/lower", 0))
		return false;
	system("ls /var/tmp/lalla/lower/local");
	if (!fsutil_mount_bind("/var/tmp/lalla/usr-local", "/var/tmp/lalla/lower/local", 0))
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

	if (setgid(0) < 0)
		log_fatal("Failed to setgid(0): %m\n");
	if (setuid(0) < 0)
		log_fatal("Failed to setuid(0): %m\n");

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
	trace("Trying to unmount the mount staging dir");
	__fsutil_tempdir_unmount(&ctx->temp);

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
	if (ctx->boot_fstype) {
		if (mount(ctx->boot_device, "/tmp/root", ctx->boot_fstype, 0, NULL) < 0) {
			log_error("Cannot mount %s file system on %s: %m", ctx->boot_fstype, ctx->boot_device);
			goto out;
		}
		root_dir = "/tmp/root";
	} else {
		const char **next, *fstype;

		for (next = default_fstypes; (fstype = *next++) != NULL; ) {
			if (mount(ctx->boot_device, "/tmp/root", fstype, 0, NULL) >= 0) {
				trace("Successfully mounted %s using %s", ctx->boot_device, fstype);
				root_dir = "/tmp/root";
				break;
			}

			trace("Failed to mount %s file system on %s: %m", fstype, ctx->boot_device);
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

static int
prune_new_image(struct wormhole_context *ctx)
{
	char *image_root = NULL;
	struct fstree_iter *it;
	struct fstree_node *node;

	pathutil_concat2(&image_root, ctx->build_root, "image");

	trace("Pruning image tree:");
	it = fstree_iterator_new(ctx->farm->tree, true);
	while ((node = fstree_iterator_next(it)) != NULL) {
		const char *image_path = __pathutil_concat2(image_root, node->relative_path);
		int dtype;

		/* Don't try to remove $build_root/image */
		if (node->parent == NULL)
			break;

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

	trace("Removing work tree at %s/work", ctx->build_root);
	fsutil_remove_recursively(__pathutil_concat2(ctx->build_root, "work"));
	return 0;
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

	trace("Now perform the pruning");
	ctx->exit_status = prune_new_image(ctx);

out:
	return ctx->exit_status;
}

static bool
record_modified_mounts_to_layer(struct wormhole_context *ctx, struct wormhole_layer *new_layer)
{
	struct mount_farm *farm = ctx->farm;
	char *image_root = NULL;
	unsigned int i;

	assert(ctx->build_root);

	if (!mount_farm_set_upper_base(farm, ctx->build_root))
		return false;

	if (!wormhole_context_resolve_layers(ctx))
		return false;

	trace("Applying layers");
	pathutil_concat2(&image_root, ctx->build_root, "image");
	for (i = 0; i < ctx->layers.count; ++i) {
		struct wormhole_layer *layer = ctx->layers.data[i];
		unsigned int j;

		for (j = 0; j < layer->stacked_directories.count; ++j) {
			const char *dir_path = layer->stacked_directories.data[j];
			const char *image_dir_path;

			image_dir_path = __pathutil_concat2(image_root, dir_path);
			if (fsutil_exists(image_dir_path)) {
				if (!strutil_array_contains(&new_layer->stacked_directories, dir_path)) {
					trace("  %s: add to stacked mounts", dir_path);
					strutil_array_append(&new_layer->stacked_directories, dir_path);
				}
			}
		}
	}

	free(image_root);
	return true;
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

	trace("Performing build stage");
	if (!wormhole_context_perform_in_container(ctx, __perform_build, false))
		return;

	/* Now post-process the build. */
	trace("Post-process build result");

	layer = wormhole_layer_new(ctx->build_target, ctx->build_root, 0);
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

	log_info("New image can be found in %s", ctx->build_root);
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

	trace("Booting OS image at %s", ctx->boot_device);
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
	OPT_RPMDB = 256,
	OPT_BOOT,
};

static struct option	long_options[] = {
	{ "debug",	no_argument,		NULL,	'd'		},
	{ "build",	required_argument,	NULL,	'B'		},
	{ "boot",	required_argument,	NULL,	OPT_BOOT	},
	{ "buildroot",	required_argument,	NULL,	'R'		},
	{ "use",	required_argument,	NULL,	'u'		},
	{ "layer",	required_argument,	NULL,	'L'		},
	{ "rpmdb",	no_argument,		NULL,	OPT_RPMDB	},

	{ NULL },
};

int
main(int argc, char **argv)
{
	struct wormhole_context *ctx;
	int exit_status = 1;
	int c;

	ctx = wormhole_context_new();

	while ((c = getopt_long(argc, argv, "B:dL:R:u:", long_options, NULL)) != EOF) {
		switch (c) {
		case 'B':
			wormhole_context_set_build(ctx, optarg);
			break;

		case OPT_BOOT:
			wormhole_context_set_boot(ctx, optarg);
			break;

		case 'd':
			tracing_increment_level();
			break;

		case 'R':
			strutil_set(&ctx->build_root, optarg);
			break;

		case 'L':
		case 'u':
			strutil_array_append(&ctx->layer_names, optarg);
			break;

		case OPT_RPMDB:
			ctx->manage_rpmdb = true;
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
