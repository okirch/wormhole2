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

	if ((root = farm->tree->root) != NULL) {
		mount_leaf_free(root);
		farm->tree->root = NULL;
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
__mount_farm_fudge_non_directory(struct mount_leaf *node, struct mount_leaf *closest_ancestor, int dtype, struct wormhole_layer *layer)
{
	trace("%s is not a directory - dt %u", node->relative_path, dtype);
	node->dtype = dtype;

	if (closest_ancestor->export_type == WORMHOLE_EXPORT_TRANSPARENT) {
		/* We get here eg for /etc/passwd if /etc is transparent.
		 * Transform this into a bind mount.
		 */
		if (dtype != DT_REG)
			return false;

		/* Transform this to a bind mount */
		node->export_type = WORMHOLE_EXPORT_TRANSPARENT;
		strutil_set(&node->fstype, "bind");

		/* Remember the layer this file comes from for later reference
		 * when we try to mount it. */
		node->bind_mount_override_layer = layer;
		return true;
	} else
	if (closest_ancestor->export_type == WORMHOLE_EXPORT_STACKED) {
		/* We get here eg for /etc/passwd if /etc is stacked.
		 * Copy the file in question to the ancestor's upperdir.
		 */
		char *src_path = NULL, *relative_path = NULL, *dst_path = NULL;
		bool ok;

		if (dtype != DT_REG)
			return false;

		relative_path = mount_leaf_relative_path(closest_ancestor, node);

		if (!mount_leaf_zap_dirs(node))
			return false;

		pathutil_concat2(&src_path, layer->image_path, node->relative_path);
		pathutil_concat2(&dst_path, closest_ancestor->upper, relative_path);
		ok = fsutil_copy_file(src_path, dst_path, NULL);
		strutil_drop(&src_path);
		strutil_drop(&dst_path);
		strutil_drop(&relative_path);

		if (!ok)
			return false;

		/* We transferred the file to the ancestor, so this node is no longer relevant */
		mount_leaf_invalidate(node);
	}

	return false;
}

static bool
__mount_farm_percolate(struct mount_leaf *node, struct mount_leaf *closest_ancestor)
{
	struct mount_leaf *child;
	unsigned int i;

	trace3("%*.*s%s(%s [%s])",
			node->depth, node->depth, "",
			__func__, node->relative_path, mount_export_type_as_string(node->export_type));
	if (node->export_type == WORMHOLE_EXPORT_STACKED) {
		unsigned int n = 0;

		if (node->attached_layers.count == 0) {
			log_error("mount_farm_percolate: internal error - %s is a %s mount but has no layers",
					node->relative_path,
					mount_export_type_as_string(node->export_type));
			return false;
		}

		for (n = node->attached_layers.count; n--; ) {
			struct wormhole_layer *layer = node->attached_layers.data[n];
			const char *image_path = __fsutil_concat2(layer->image_path, node->relative_path);
			int dtype;

			if ((dtype = fsutil_get_dtype(image_path)) >= 0) {
				if (dtype != DT_DIR)
					__mount_farm_fudge_non_directory(node, closest_ancestor, dtype, layer);
				break;
			}
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
		 * the required mount point.
		 * If not, we could insert a lower layer at the very bottom
		 * of the stack that contains the missing mount points. */
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
		trace2("Moving attached layers of %s to %s", node->relative_path, closest_ancestor->relative_path);
		for (i = 0; i < node->attached_layers.count; ++i) {
			struct wormhole_layer *layer = node->attached_layers.data[i];

			wormhole_layer_array_append_unique(&closest_ancestor->attached_layers, layer);
		}
		wormhole_layer_array_destroy(&node->attached_layers);

		/* No longer mount anything on this node */
		mount_leaf_invalidate(node);
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

	if (node->export_type == WORMHOLE_EXPORT_TRANSPARENT && node->fstype == NULL) {
		log_error("Bug/problem: someone forgot to mark %s as a bind mount", node->relative_path);
		return false;
	}

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
	num_mounted = 0;

	if (!mount_leaf_traverse(farm->tree->root, __mount_farm_mount_leaf))
		return false;

	farm->num_mounts = num_mounted;
	return true;
}
