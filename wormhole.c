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

bool			wormhole_in_chroot = false;

static char *
concat_path(const char *parent, const char *name)
{
	const char *path = __fsutil_concat2(parent, name);

	if (path)
		return strdup(path);
	return NULL;
}

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

	fstree = fstree_new();
	if (!fstree_discover(NULL, __mount_farm_discover_callback, fstree)) {
		log_error("Mount state discovery failed\n");
		return false;
	}

	it = fstree_iterator_new(fstree);
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
	it = fstree_iterator_new(farm->tree);
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
		trace("Final tree:");
		mount_farm_print_tree(farm);
		trace("---");

		okay = true;
	}

out:
	return okay;
}

bool
mount_farm_assemble_for_build(struct mount_farm *farm, struct wormhole_layer_array *layers)
{
	log_error("Currently not implemented");
	return false;
}

bool
mount_farm_assemble_for_run(struct mount_farm *farm, struct wormhole_layer_array *layers)
{
	return mount_farm_discover(farm, layers);
}

static int
run_the_command(struct wormhole_context *ctx)
{
	int status, exit_status;

	trace("Running command:");
	if (!procutil_command_run(&ctx->command, &status)) {
		exit_status = 12;
	} else
	if (!procutil_get_exit_status(status, &exit_status)) {
		log_error("Command %s %s", ctx->command.argv[0], procutil_child_status_describe(status));
		exit_status = 13;
	} else {
		trace("Command exited with status %d\n", exit_status);
	}

	return exit_status;
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

	trace("%s()", __func__);
	ctx->farm->tree->root->export_type = WORMHOLE_EXPORT_ROOT;

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

	if (wormhole_in_chroot) {
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
	int status;
	pid_t pid;

	if (nofork) {
		pid = 0;
	} else {
		pid = fork();
		if (pid < 0)
			log_fatal("Unable to fork: %m");
	}

	if (pid == 0) {
		int exit_status;

		trace("%s: executing subprocess callback %p", __func__, fn);
		exit_status = fn(ctx);
		trace("%s: subprocess going to terminate normally, exit status = %d", __func__, exit_status);
		exit(exit_status);
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

	trace("Container sub-process exited with status %d", ctx->exit_status);
	return true;
}

static int
__perform_boot(struct wormhole_context *ctx)
{
	static const char *default_fstypes[] = {
		"btrfs", "ext4", "xfs", NULL,
	};

	ctx->exit_status = 100;

	if (!wormhole_context_detach(ctx))
		goto out;

	/* make sure there's a tmpfs at /tmp */
	if (!fsutil_mount_tmpfs("/tmp"))
		goto out;

	if (!fsutil_makedirs("/tmp/root", 0755))
		goto out;

	ctx->farm = mount_farm_new("/tmp/unused");
	if (ctx->boot_fstype) {
		if (mount(ctx->boot_device, "/tmp/root", ctx->boot_fstype, 0, NULL) < 0) {
			log_error("Cannot mount %s file system on %s: %m", ctx->boot_fstype, ctx->boot_device);
			goto out;
		}
		strutil_set(&ctx->farm->chroot, "/tmp/root");
	} else {
		const char **next, *fstype;

		for (next = default_fstypes; (fstype = *next++) != NULL; ) {
			if (mount(ctx->boot_device, "/tmp/root", fstype, 0, NULL) >= 0) {
				trace("Successfully mounted %s using %s", ctx->boot_device, fstype);
				strutil_set(&ctx->farm->chroot, "/tmp/root");
				break;
			}

			trace("Failed to mount %s file system on %s: %m", fstype, ctx->boot_device);
		}
	}

	trace("chroot=%s", ctx->farm->chroot);
	if (ctx->farm->chroot == NULL) {
		log_error("No root file system found");
		goto out;
	}

	if (!wormhole_context_switch_root(ctx))
		goto out;

	if (ctx->command.argv == NULL) {
		char *argv_init[] = {
			"/bin/init", NULL
		};
		procutil_command_init(&ctx->command, argv_init);
	}

	procutil_command_exec(&ctx->command, ctx->command.argv[0]);
	log_error("Failed to execute init process");

out:
	return ctx->exit_status;
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
		const char *rpmdb_orig = RPMDB_PATH;
		unsigned int i;

		trace("Building RPM database");
		for (i = 0; i < ctx->layers.count; ++i) {
			struct wormhole_layer *layer = ctx->layers.data[i];

			trace("layer %s root %s isdir %u",
					layer->name, layer->path,
					fsutil_isdir(layer->path));
			{
				char x[1024];
				sprintf(x, "find %s -ls", layer->rpmdb_path);
				system(x);
			}
			if (!wormhole_layer_patch_rpmdb(ctx->layers.data[i], rpmdb_orig, ctx->farm->chroot))
				goto out;
		}

		{
			char x[1024];

			sprintf(x, "rpm --root %s -V libsqlite3-0", ctx->farm->chroot);
			trace("about to call %s", x);
			system(x);
			sprintf(x, "rpm --root %s -qi python310-base", ctx->farm->chroot);
			trace("about to call %s", x);
			system(x);
		}
	}

	if (!wormhole_context_switch_root(ctx))
		goto out;

	return run_the_command(ctx);

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
	struct fstree_node *mount;

	if (d->d_type != DT_DIR)
		return FTW_CONTINUE;

	pathutil_concat2(&full_path, dir_path, d->d_name);

	if (!(relative_path = fsutil_strip_path_prefix(full_path, prune->image_root)))
		return FTW_ERROR;

	mount = mount_farm_find_leaf(prune->mounts, relative_path);
	if (mount) {
		bool try_to_prune = false;

		if (fstree_node_is_mountpoint(mount)
		 || !fstree_node_is_below_mountpoint(mount))
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

	/* FIXME: remove files:
	 *   - /usr/lib/sysimage/rpm
	 *   - /etc/ld.so.conf
	 *   - /var/cache/ldconfig
	 */

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

	trace("Performing build stage");
	if (!wormhole_context_perform_in_container(ctx, __perform_build, false))
		return;

	/* Now post-process the build. */
	trace("Post-process build result");
	if (!wormhole_context_perform_in_container(ctx, __prune_build, false))
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

	trace("Booting OS");
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

	if (optind < argc)
		wormhole_context_set_command(ctx, argv + optind);
	else
	if (ctx->purpose == PURPOSE_BUILD || ctx->purpose == PURPOSE_USE)
		log_fatal("Missing command to be executed\n");

	if (!fsutil_dir_is_mountpoint("/")) {
		log_warning("Running inside what looks like a chroot environment.");
		wormhole_in_chroot = true;
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
