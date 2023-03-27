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

/*
 * mount_config objects and arrays
 */
struct mount_config *
mount_config_new(const char *path, int dtype)
{
	struct mount_config *mnt;

	if (dtype < 0)
		dtype = DT_UNKNOWN;

	mnt = calloc(1, sizeof(*mnt));
	mnt->path = pathutil_sanitize(path);
	mnt->refcount = 1;
	mnt->dtype = dtype;

	return mnt;
}

static void
mount_config_free(struct mount_config *mnt)
{
	assert(mnt->refcount == 0);
	strutil_drop(&mnt->path);
	free(mnt);
}

void
mount_config_release(struct mount_config *mnt)
{
	assert(mnt->refcount);
	if (--(mnt->refcount) == 0)
		mount_config_free(mnt);
}

static inline bool
__mount_config_update(struct mount_config *mnt, int dtype, mount_mode_t mode, mount_origin_t origin)
{
	if (dtype < 0)
		return true;

	if (mnt->dtype == DT_UNKNOWN) {
		mnt->dtype = dtype;
	} else if (mnt->dtype != dtype) {
		log_warning("%s: reconfigured mount from dtype %u to %u",
				mnt->path, mnt->dtype, dtype);
		return false;
	}

	/* For now, just overwrite and never complain */
	mnt->mode = mode;
	mnt->origin = origin;

	return true;
}

void
mount_config_array_init(struct mount_config_array *a)
{
	memset(a, 0, sizeof(*a));
}

void
mount_config_array_destroy(struct mount_config_array *a)
{
	unsigned int i;

	for (i = 0; i < a->count; ++i)
		mount_config_release(a->data[i]);
	memset(a, 0, sizeof(*a));
}

static void
__mount_config_array_append(struct mount_config_array *a, struct mount_config *mnt, bool transfer_ownership)
{
	if ((a->count % 16) == 0)
		a->data = realloc(a->data, (a->count + 16) * sizeof(a->data[0]));
	a->data[a->count++] = mnt;

	if (transfer_ownership) {
		/* Do NOT increment the refcount, assume the caller does this when adding
		 * an existing mount. */
	} else {
		mnt->refcount++;
	}
}

static struct mount_config *
mount_config_array_find(struct mount_config_array *a, const char *path, bool create)
{
	struct mount_config *mnt;
	unsigned int i;

	for (i = 0; i < a->count; ++i) {
		mnt = a->data[i];
		if (!strcmp(mnt->path, path))
			return mnt;
	}

	if (!create)
		return NULL;

	mnt = mount_config_new(path, -1);
	__mount_config_array_append(a, mnt, false);

	return mnt;
}

struct mount_config *
mount_config_array_get(struct mount_config_array *a, const char *path)
{
	char *sane_path = pathutil_sanitize(path);
	struct mount_config *found;

	found = mount_config_array_find(a, sane_path, false);
	strutil_drop(&sane_path);

	return found;
}

struct mount_config *
mount_config_array_add(struct mount_config_array *a, const char *path, int dtype, mount_origin_t origin, mount_mode_t mode)
{
	struct mount_config *mnt;

	mnt = mount_config_array_find(a, path, true);
	if (mnt && !__mount_config_update(mnt, dtype, mode, origin))
		return NULL;
	return mnt;
}

struct mount_config *
mount_config_array_append(struct mount_config_array *a, struct mount_config *mnt)
{
	struct mount_config *existing;

	existing = mount_config_array_find(a, mnt->path, false);
	if (existing == NULL) {
		__mount_config_array_append(a, mnt, true);
		return mnt;
	}

	if (!__mount_config_update(existing, mnt->dtype, mnt->mode, mnt->origin))
		return NULL;

	return existing;
}

/*
 * The actual mount farms
 */
struct mount_farm *
mount_farm_new(const char *farm_root)
{
	struct mount_farm *farm;

	farm = calloc(1, sizeof(*farm));

	(void) fsutil_makedirs(farm_root, 0755);

	pathutil_concat2(&farm->upper_base, farm_root, "upper");
	pathutil_concat2(&farm->work_base, farm_root, "work");
	pathutil_concat2(&farm->chroot, farm_root, "root");

	farm->tree = fstree_new(farm->chroot);
	farm->tree->root->export_type = WORMHOLE_EXPORT_ROOT;

	return farm;
}

void
mount_farm_free(struct mount_farm *farm)
{
	struct fstree_node *root;

	if ((root = farm->tree->root) != NULL) {
		fstree_node_free(root);
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
	fstree_print(farm->tree);
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

struct fstree_node *
mount_farm_find_leaf(struct mount_farm *farm, const char *relative_path)
{
	return fstree_node_lookup(farm->tree->root, relative_path, false);
}

bool
mount_farm_has_mount_for(struct mount_farm *farm, const char *path)
{
	struct fstree_node *node;

	if (!(node = fstree_node_lookup(farm->tree->root, path, false)))
		return false;

	return fstree_node_is_mountpoint(node);
}

static bool
__mount_farm_fudge_non_directory(struct fstree_node *node, struct fstree_node *closest_ancestor, int dtype, struct wormhole_layer *layer)
{
	trace("%s is not a directory but a %s", node->relative_path, fsutil_dtype_as_string(dtype));
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

		relative_path = fstree_node_relative_path(closest_ancestor, node);

		/* As we're transferring the file to our ancestor, this mount is no longer
		 * relevant. As a side effect, this removes the corresponding mount point
		 * directory below upperdir, allowing us to copy the regular file into
		 * upperdir at the same location. */
		fstree_node_invalidate(node);

		pathutil_concat2(&src_path, layer->image_path, node->relative_path);
		pathutil_concat2(&dst_path, closest_ancestor->upper, relative_path);
		ok = fsutil_copy_file(src_path, dst_path, NULL);
		strutil_drop(&src_path);
		strutil_drop(&dst_path);
		strutil_drop(&relative_path);

		if (!ok)
			return false;
	}

	return false;
}

static bool
__mount_farm_percolate(struct fstree_node *node, struct fstree_node *closest_ancestor)
{
	struct fstree_node *child;
	unsigned int i;

	trace3("%*.*s%s(%s [%s:%s])",
			node->depth, node->depth, "",
			__func__, node->relative_path, mount_export_type_as_string(node->export_type), node->fstype);

	if (node->export_type == WORMHOLE_EXPORT_HIDE)
		return true;

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
			const char *image_path = __pathutil_concat2(layer->image_path, node->relative_path);
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
	case EXPORT_COMBINATION(TRANSPARENT, STACKED):
	case EXPORT_COMBINATION(TRANSPARENT, SEMITRANSPARENT):
		/* We're adding a mount inside some transparent
		 * mount. All we can do is hope that someone created the
		 * mount point for us.
		 */
		break;

	case EXPORT_COMBINATION(STACKED, TRANSPARENT):
	case EXPORT_COMBINATION(STACKED, SEMITRANSPARENT):
		/* FIXME: verify that any of the layers mounted on this
		 * stacked mount point (aka overlay) provides
		 * the required mount point.
		 * If not, we could insert a lower layer at the very bottom
		 * of the stack that contains the missing mount points. */
		break;

	case EXPORT_COMBINATION(ROOT, STACKED):
		/* Stacked mount directly below the root */
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
		fstree_node_invalidate(node);
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
	struct fstree_node *root = farm->tree->root;

	return __mount_farm_percolate(root, root);
}

struct fstree_node *
fstree_add_export(struct fstree *fstree, const char *system_path, unsigned int export_type, int dtype, struct wormhole_layer *layer, int flags)
{
	struct fstree_node *node;

	if (!(node = fstree_node_lookup(fstree->root, system_path, true)))
		return NULL;

	if (node->export_type == WORMHOLE_EXPORT_NONE) {
		trace2("  mount farm: add new %s mount %s", mount_export_type_as_string(export_type),  system_path);
		node->export_type = export_type;
	} else
	if (node->export_type != export_type) {
		if (flags & FSTREE_QUIET)
			return NULL;
		log_error("%s: conflicting export types (%s vs %s)", system_path,
				mount_export_type_as_string(node->export_type),
				mount_export_type_as_string(export_type));
		return NULL;
	}

	if (node->dtype == DT_UNKNOWN || node->dtype < 0)
		node->dtype = dtype;
	else if (node->dtype != dtype) {
		if (flags & FSTREE_QUIET) {
			trace("%s: conflicting file types (%u vs %u)", system_path, node->dtype, dtype);
		} else {
			log_error("%s: conflicting file types (%u vs %u)", system_path, node->dtype, dtype);
		}
		return NULL;
	}

	if (flags & FSTREE_ADD_REPLACE_LAYERS)
		wormhole_layer_array_destroy(&node->attached_layers);

	if (layer)
		wormhole_layer_array_append(&node->attached_layers, layer);
	return node;
}

struct fstree_node *
mount_farm_add_stacked(struct mount_farm *farm, const char *system_path, struct wormhole_layer *layer)
{
	return fstree_add_export(farm->tree, system_path, WORMHOLE_EXPORT_STACKED, DT_DIR, layer, 0);
}

struct fstree_node *
mount_farm_add_transparent(struct mount_farm *farm, const char *system_path, int dtype, struct wormhole_layer *layer)
{
	return fstree_add_export(farm->tree, system_path, WORMHOLE_EXPORT_TRANSPARENT, dtype, layer, 0);
}

struct fstree_node *
mount_farm_add_mount(struct mount_farm *farm, const struct mount_config *mnt, struct wormhole_layer *layer)
{
	int export_type, flags = 0;

	if (mnt->origin == MOUNT_ORIGIN_LAYER && mnt->mode == MOUNT_MODE_OVERLAY)
		export_type = WORMHOLE_EXPORT_STACKED;
	else
	if (mnt->origin == MOUNT_ORIGIN_SYSTEM && mnt->mode == MOUNT_MODE_BIND)
		export_type = WORMHOLE_EXPORT_TRANSPARENT;
	else
	if (mnt->origin == MOUNT_ORIGIN_SYSTEM && mnt->mode == MOUNT_MODE_OVERLAY) {
		export_type = WORMHOLE_EXPORT_SEMITRANSPARENT;
		layer = wormhole_layer_get_system();
		flags = FSTREE_ADD_REPLACE_LAYERS;
	} else {
		log_error("%s: cannot add %s: invalid combination of origin/mode", __func__, mnt->path);
		return false;
	}
	return fstree_add_export(farm->tree, mnt->path, export_type, mnt->dtype, layer, flags);
}

bool
mount_farm_add_missing_children(struct mount_farm *farm, const char *system_path)
{
	struct fstree_node *dir_node;
	DIR *dir;
	struct dirent *d;
	bool okay = false;

	trace3("%s(%s)", __func__, system_path);
	if (!(dir_node = fstree_node_lookup(farm->tree->root, system_path, false))) {
		trace("%s: oops, no mount node for %s?!", __func__, system_path);
		return false;
	}

	if (dir_node->export_type == WORMHOLE_EXPORT_HIDE)
		return true;

	if (!(dir = opendir(system_path))) {
		log_error("%s: %s: %m", __func__, system_path);
		return false;
	}

	while ((d = readdir(dir)) != NULL) {
		struct fstree_node *child;

		if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
			continue;

		if (dir_node->parent == NULL && d->d_type != DT_DIR) {
			trace("Ignoring top-level file /%s", d->d_name);
			continue;
		}

		child = fstree_node_lookup(dir_node, d->d_name, false);
		if (child == NULL) {
			const char *path = __pathutil_concat2(system_path, d->d_name);
			int dtype;

			if ((dtype = fsutil_get_dtype(path)) < 0)
				goto out;

			child = mount_farm_add_transparent(farm, path, dtype, NULL);
			if (child == NULL) {
				log_error("%s: cannot add transparent mount for %s", __func__, path);
				goto out;
			}
			trace3("%s: added a bind mount for %s", __func__, child->relative_path);
			fstree_node_set_fstype(child, "bind", farm);
		}
	}

	okay = true;

out:
	closedir(dir);
	return okay;
}

static bool
__mount_farm_mount_one(const struct fstree_node *node)
{
	if (node->fstype == NULL)
		return true;

	if (!fstree_node_mount(node))
		return false;

	num_mounted++;
	return true;
}

bool
mount_farm_mount_all(struct mount_farm *farm)
{
	num_mounted = 0;

	if (!fstree_node_traverse(farm->tree->root, __mount_farm_mount_one))
		return false;

	farm->num_mounts = num_mounted;
	return true;
}
