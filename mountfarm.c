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
	farm->tree = mount_state_new();

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

	if ((root = farm->tree->root) != NULL) {
		mount_leaf_free(root);
		farm->tree->root = NULL;
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
	mount_tree_print(farm->tree->root);
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
	return mount_leaf_lookup(farm->tree->root, relative_path, false);
}

bool
mount_farm_has_mount_for(struct mount_farm *farm, const char *path)
{
	struct mount_leaf *leaf;

	if (!(leaf = mount_leaf_lookup(farm->tree->root, path, false)))
		return false;

	return mount_leaf_is_mountpoint(leaf);
}

static bool
__mount_farm_percolate(struct mount_leaf *node, struct mount_leaf *closest_ancestor)
{
	struct mount_leaf *child;
	unsigned int i;

	// trace("%s(%s)", __func__, node->relative_path);
	if (node->export_type == WORMHOLE_EXPORT_STACKED) {
		if (node->attached_layers.count == 0) {
			log_error("mount_farm_percolate: internal error - %s is a %s mount but has no layers",
					node->relative_path,
					mount_export_type_as_string(node->export_type));
			return false;
		}
	}

#define EXPORT_COMBINATION(ancestor, self) \
	((WORMHOLE_EXPORT_##ancestor) << 8 | (WORMHOLE_EXPORT_##self))

	switch ((closest_ancestor->export_type << 8) | node->export_type) {
	case EXPORT_COMBINATION(ROOT, ROOT):
		/* the root node itself */
		break;

	case EXPORT_COMBINATION(ROOT, NONE):
		/* Internal node directly below the root. Mark it as a root node as well */
		node->export_type = WORMHOLE_EXPORT_ROOT;
		break;

	case EXPORT_COMBINATION(ROOT, TRANSPARENT):
		/* Transparent mount directly below the root */
		break;

	case EXPORT_COMBINATION(TRANSPARENT, TRANSPARENT):
		/* We're adding a transparent mount inside a transparent
		 * mount. All we can do is hope that someone created the
		 * mount point for us.
		 */
		break;

	case EXPORT_COMBINATION(STACKED, TRANSPARENT):
		/* FIXME: verify that any of the layers mounted on this
		 * stacked mount point (aka overlay) provides
		 * the required mount point. */
		break;

	case EXPORT_COMBINATION(ROOT, STACKED):
		/* Stacked mount directly below the root */
		break;

	case EXPORT_COMBINATION(TRANSPARENT, STACKED):
		/* We're adding a stacked mount inside a transparent mount. */
		break;

	case EXPORT_COMBINATION(STACKED, STACKED):
		/* A stacked mount inside a stacked mount - just transfer the layers
		 * attached here to the ancestor.
		 */
		for (i = 0; i < node->attached_layers.count; ++i) {
			struct wormhole_layer *layer = node->attached_layers.data[i];

			wormhole_layer_array_append(&closest_ancestor->attached_layers, layer);
		}
		wormhole_layer_array_destroy(&node->attached_layers);
		node->export_type = WORMHOLE_EXPORT_NONE;
		break;

	default:
		if (node->export_type != WORMHOLE_EXPORT_NONE) {
			log_error("%s: unsupported export type combination %s inside %s", 
					node->relative_path, 
					mount_export_type_as_string(node->export_type),
					mount_export_type_as_string(closest_ancestor->export_type));
			return false;
		}
		break;
	}

	if (node->export_type != WORMHOLE_EXPORT_NONE)
		closest_ancestor = node;

	for (child = node->children; child != NULL; child = child->next) {
		if (!__mount_farm_percolate(child, closest_ancestor))
			return false;
	}

	return true;
}

bool
mount_farm_percolate(struct mount_farm *farm)
{
	struct mount_leaf *root = farm->tree->root;

	return __mount_farm_percolate(root, root);
}

struct mount_leaf *
mount_state_add_export(struct mount_state *state, const char *system_path, unsigned int export_type, struct wormhole_layer *layer)
{
	struct mount_leaf *leaf;

	if (!(leaf = mount_leaf_lookup(state->root, system_path, true)))
		return NULL;

	if (leaf->export_type == WORMHOLE_EXPORT_NONE) {
		trace2("  mount farm: add new %s mount %s", mount_export_type_as_string(export_type),  system_path);
		leaf->export_type = export_type;
	} else
	if (leaf->export_type != export_type) {
		log_error("%s: conflicting export types (%s vs %s", system_path,
				mount_export_type_as_string(leaf->export_type),
				mount_export_type_as_string(export_type));
		return NULL;
	}

	if (layer)
		wormhole_layer_array_append(&leaf->attached_layers, layer);
	return leaf;
}

struct mount_leaf *
mount_farm_add_stacked(struct mount_farm *farm, const char *system_path, struct wormhole_layer *layer)
{
	return mount_state_add_export(farm->tree, system_path, WORMHOLE_EXPORT_STACKED, layer);
}

struct mount_leaf *
mount_farm_add_transparent(struct mount_farm *farm, const char *system_path, struct wormhole_layer *layer)
{
	return mount_state_add_export(farm->tree, system_path, WORMHOLE_EXPORT_TRANSPARENT, layer);
}

bool
mount_farm_add_missing_children(struct mount_farm *farm, const char *system_path)
{
	struct mount_leaf *dir_node;
	DIR *dir;
	struct dirent *d;
	bool okay = false;

	if (!(dir_node = mount_leaf_lookup(farm->tree->root, system_path, false))) {
		trace("%s: oops, no mount node for %s?!", __func__, system_path);
		return false;
	}

	if (!(dir = opendir(system_path))) {
		log_error("%s: %s: %m", __func__, system_path);
		return false;
	}

	while ((d = readdir(dir)) != NULL) {
		struct mount_leaf *child;

		if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
			continue;

		if (dir_node->parent == NULL && d->d_type != DT_DIR) {
			trace("Ignoring top-level file /%s", d->d_name);
			continue;
		}

		child = mount_leaf_lookup(dir_node, d->d_name, false);
		if (child == NULL) {
			child = mount_farm_add_transparent(farm, __fsutil_concat2(system_path, d->d_name), NULL);
			if (child == NULL) {
				log_error("%s: cannot add transparent mount for %s/%s", __func__, system_path, d->d_name);
				goto out;
			}
			mount_leaf_set_fstype(child, "bind", farm);
		}
	}

	okay = true;

out:
	closedir(dir);
	return okay;
}

struct mount_leaf *
mount_farm_add_system_dir(struct mount_farm *farm, const char *system_path)
{
	struct mount_leaf *leaf;

	if (!(leaf = mount_leaf_lookup(farm->tree->root, system_path, true)))
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

	if (!(leaf = mount_leaf_lookup(farm->tree->root, system_path, true)))
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

	if (!mount_leaf_traverse(farm->tree->root, __mount_farm_mount_leaf))
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

