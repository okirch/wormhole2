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

struct mount_farm *
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

void
mount_farm_print_tree(struct mount_farm *farm)
{
	mount_tree_print(farm->root);
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

struct mount_leaf *
mount_farm_add_stacked(struct mount_farm *farm, const char *system_path)
{
	struct mount_leaf *leaf, *up;

	if (!(leaf = mount_leaf_lookup(farm->root, system_path, true)))
		return NULL;

	if (leaf->export_type == WORMHOLE_EXPORT_STACKED)
		return leaf;

	if (leaf->export_type != WORMHOLE_EXPORT_NONE) {
		log_error("%s: conflicting export types", system_path);
		return NULL;
	}

	for (up = leaf->parent; up && up->export_type == WORMHOLE_EXPORT_NONE; up = up->parent)
		;

	if (up != NULL) {
		/* Stacking something else below a stacked mount is not a problem */
		if (up->export_type == WORMHOLE_EXPORT_STACKED)
			return leaf;

		if (up->export_type != WORMHOLE_EXPORT_TRANSPARENT) {
			log_error("Cannot create stacked mount %s inside another stacked mount (%s)",
					system_path, up->relative_path);
			leaf->export_type = WORMHOLE_EXPORT_ERROR;
			return NULL;
		}
	}

	trace2("  mount farm: add new stacked mount %s", system_path);
	leaf->export_type = WORMHOLE_EXPORT_STACKED;
	return leaf;
}

struct mount_leaf *
mount_farm_add_transparent(struct mount_farm *farm, const char *system_path)
{
	struct mount_leaf *leaf, *up;

	if (!(leaf = mount_leaf_lookup(farm->root, system_path, true)))
		return NULL;

	if (leaf->export_type == WORMHOLE_EXPORT_TRANSPARENT)
		return leaf;

	for (up = leaf; up && up->export_type == WORMHOLE_EXPORT_NONE; up = up->parent)
		;

	if (up != NULL && up->export_type != WORMHOLE_EXPORT_TRANSPARENT) {
		log_error("Cannot create transparent mount %s inside a mount of different type (%s)",
				system_path, up->relative_path);
		leaf->export_type = WORMHOLE_EXPORT_ERROR;
		return NULL;
	}

	trace2("  mount farm: add new transparent mount %s", system_path);
	leaf->export_type = WORMHOLE_EXPORT_TRANSPARENT;
	return leaf;
}

struct mount_leaf *
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

bool
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

