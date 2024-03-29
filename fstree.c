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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h> /* just for fstree_node_zap_dirs() */
#include <assert.h>

#include "wormhole2.h"
#include "paths.h"
#include "tracing.h"
#include "util.h"

struct fsroot *
fsroot_new(const char *root_path)
{
	struct fsroot *fsroot;

	fsroot = calloc(1, sizeof(*fsroot));
	strutil_set(&fsroot->path, root_path);
	return fsroot;
}

void
fsroot_free(struct fsroot *fsroot)
{
	strutil_drop(&fsroot->path);
	free(fsroot);
}

struct fstree *
fstree_new(const char *root_path)
{
	struct fsroot *root_location = NULL;
	struct fstree *fstree;

	if (root_path)
		root_location = fsroot_new(root_path);

	fstree = calloc(1, sizeof(*fstree));
	fstree->root_location = root_location;
	fstree->root = fstree_node_new("", "/", root_location);

	return fstree;
}

void
fstree_free(struct fstree *fstree)
{
	struct fstree_node *root;

	if ((root = fstree->root) != NULL) {
		fstree_node_free(root);
		fstree->root = NULL;
	}

	if (fstree->root_location) {
		fsroot_free(fstree->root_location);
		fstree->root_location = NULL;
	}
}

struct fstree_node *
fstree_create_leaf(struct fstree *fstree, const char *relative_path)
{
	return fstree_node_lookup(fstree->root, relative_path, true);
}

const char *
fstree_get_full_path(struct fstree *fstree, const char *relative_path)
{
	struct fstree_node *node;

	node = fstree_node_lookup(fstree->root, relative_path, true);
	return node->full_path;
}

void
fstree_node_free(struct fstree_node *node)
{
	struct fstree_node *child;

	node->parent = NULL;

	while ((child = node->children) != NULL) {
		node->children = child->next;
		fstree_node_free(child);
	}

	strutil_drop(&node->relative_path);
	strutil_drop(&node->full_path);
	strutil_drop(&node->upper);
	strutil_drop(&node->work);

	/* Destroys attached_layers and the mount_req */
	fstree_node_reset(node);
}

struct fstree_node *
fstree_node_new(const char *name, const char *relative_path, const struct fsroot *root)
{
	struct fstree_node *node;

	node = calloc(1, sizeof(*node));
	node->root = root;
	node->name = strdup(name);
	node->relative_path = strdup(relative_path);

	if (root) {
		pathutil_concat2(&node->full_path, root->path, relative_path);
	} else {
		strutil_set(&node->full_path, relative_path);
	}

	node->dtype = -1;

	return node;
}

inline bool
fstree_node_is_mountpoint(const struct fstree_node *node)
{
	return node->mount_ops != NULL;
}

inline bool
fstree_node_is_below_mountpoint(const struct fstree_node *node)
{
	while (node) {
		if (node->mount_ops != NULL)
			return true;
		node = node->parent;
	}
	return false;
}

struct fstree_node *
fstree_node_lookup(struct fstree_node *parent, const char *relative_path, bool create)
{
	struct pathutil_parser path_parser;
	struct fstree_node *node = NULL, **pos;

	pathutil_parser_init(&path_parser, relative_path);

	/* If the path is empty, return the node itself */
	node = parent;

	pos = &parent->children;

	while (pathutil_parser_next(&path_parser)) {
		const char *name = path_parser.namebuf;

		while ((node = *pos) != NULL) {
			if (!strcmp(node->name, name))
				break;
			pos = &(node->next);
		}

		if (node == NULL) {
			if (!create)
				break;

			// trace3("Creating node for %s as child of %s\n", path_parser.pathbuf, parent->relative_path);
			node = fstree_node_new(path_parser.namebuf, path_parser.pathbuf, parent->root);
			node->depth = parent->depth + 1;

			node->parent = parent;
			*pos = node;
		}

		parent = node;
		pos = &node->children;
	}

	return node;
}

struct fstree_node *
fstree_node_closest_ancestor(struct fstree_node *parent, const char *relative_path)
{
	struct pathutil_parser path_parser;
	struct fstree_node *node = NULL, *ancestor, **pos;

	pathutil_parser_init(&path_parser, relative_path);

	/* If the path is empty, return the node itself */
	ancestor = parent;

	pos = &parent->children;

	while (pathutil_parser_next(&path_parser)) {
		const char *name = path_parser.namebuf;

		while ((node = *pos) != NULL) {
			if (!strcmp(node->name, name))
				break;
			pos = &(node->next);
		}

		if (node == NULL)
			break;

		if (node->export_type != WORMHOLE_EXPORT_NONE)
			ancestor = node;

		parent = node;
		pos = &node->children;
	}

	return ancestor;
}

/*
 * Given a fnmatch pattern, mark all tree nodes as hidden.
 */
static inline void
fstree_node_hide(struct fstree_node *node)
{
	struct fstree_node *child;

	trace2("Hide %s", node->relative_path);
	node->export_type = WORMHOLE_EXPORT_HIDE;
	node->mount_ops = NULL;
	for (child = node->children; child; child = child->next)
		fstree_node_hide(child);
}

bool
fstree_hide_pattern(struct fstree *fstree, const char *pattern)
{
	struct pathutil_parser path_parser;
	struct fstree_node *node = NULL, **pos = NULL;

	pathutil_parser_init(&path_parser, pattern);

	/* If the path is empty, return the node itself */
	node = fstree->root;

	while (pathutil_parser_next(&path_parser)) {
		const char *name = path_parser.namebuf;

		if (!strcmp(name, "*")) {
			struct fstree_node *child = NULL;

			for (child = node->children; child; child = child->next)
				fstree_node_hide(child);
			return true;
		}

		if (strchr(name, '*') || strchr(name, '?')) {
			log_error("%s: Cannot handle pattern \"%s\"", __func__, pattern);
			return false;
		}

		pos = &node->children;
		while ((node = *pos) != NULL) {
			if (!strcmp(node->name, name))
				break;
			pos = &(node->next);
		}

		if (node == NULL)
			return false;
	}

	if (node)
		fstree_node_hide(node);

	return node;
}

char *
fstree_node_relative_path(struct fstree_node *ancestor, struct fstree_node *node)
{
	char relative_path[PATH_MAX + 1];
	unsigned int pos, n;

	pos = sizeof(relative_path);
	relative_path[--pos] = '\0';

	while (node != ancestor) {
		n = strlen(node->name);

		if (pos < n + 1)
			return NULL;
		if (relative_path[pos] != '\0')
			relative_path[--pos] = '/';
		pos -= n;
		memcpy(&relative_path[pos], node->name, n);

		node = node->parent;
	}

	return strdup(&relative_path[pos]);
}

bool
fstree_node_zap_dirs(struct fstree_node *node)
{
	const char *to_zap[10];
	unsigned int i = 0;

	if (node->upper)
		to_zap[i++] = node->upper;
	if (node->work)
		to_zap[i++] = node->work;
	if (node->mount.mount_point)
		to_zap[i++] = node->mount.mount_point;

	while (i--) {
		const char *dir = to_zap[i];
		if (rmdir(dir) < 0 && errno != ENOENT && errno != ENOTEMPTY) {
			if (errno != ENOTDIR || unlink(dir) < 0) {
				log_error("cannot remove %s: %m", dir);
				return false;
			}
		}
	}

	return true;
}

bool
fstree_node_set_fstype(struct fstree_node *node, mount_ops_t *mount_ops, struct mount_farm *farm)
{
	if (node->mount_ops == NULL) {
		node->mount_ops = mount_ops;
	} else if (node->mount_ops != mount_ops) {
		log_error("VFS type of %s changes from %s to %s\n", node->relative_path, node->mount_ops->name, mount_ops->name);
		return false;
	}

	/* FIXME - we only need to set upper and work for transparent mounts */
	if (!node->upper)
		pathutil_concat2(&node->upper, farm->upper_base, node->relative_path);

	if (!node->work)
		pathutil_concat2(&node->work, farm->work_base, node->relative_path);

	if (!node->mount.mount_point)
		pathutil_concat2(&node->mount.mount_point, farm->chroot, node->relative_path);

	return node->upper && node->work && node->mount.mount_point;
}

void
fstree_node_reset(struct fstree_node *node)
{
	node->mount_ops = NULL;
	node->export_type = WORMHOLE_EXPORT_NONE;
	node->export_flags = 0;
	node->dtype = DT_UNKNOWN;
	wormhole_layer_array_destroy(&node->attached_layers);
	fsutil_mount_req_destroy(&node->mount);
}

/*
 * Change a node from a mount to an internal, non-mount node
 */
void
fstree_node_invalidate(struct fstree_node *node)
{
	if (node->export_type != WORMHOLE_EXPORT_ROOT)
		node->export_type = WORMHOLE_EXPORT_NONE;

	node->mount_ops = NULL;

	fstree_node_zap_dirs(node);
	fsutil_mount_req_destroy(&node->mount);
	strutil_drop(&node->upper);
	strutil_drop(&node->work);
}

char *
fstree_node_build_lowerspec(const struct fstree_node *node, bool include_host_dir)
{
	const struct wormhole_layer_array *layers = &node->attached_layers;
	struct strutil_array dirs = { 0, };
	unsigned int n;
	char *result;

	trace3("%s(%s): %u layers", __func__, node->relative_path, layers->count);
	for (n = layers->count; n--; ) {
		struct wormhole_layer *layer = layers->data[n];

		strutil_array_append(&dirs, __pathutil_concat2(layer->image_path, node->relative_path));
	}

	if (dirs.count == 0) {
		log_error("Cannot build lowerdir spec for %s: no directories given", node->relative_path);
		return NULL;
	}

	if (include_host_dir && strcmp(dirs.data[dirs.count-1], node->relative_path))
		strutil_array_append(&dirs, node->relative_path);

	result = strutil_array_join(&dirs, ":");
	strutil_array_destroy(&dirs);

	return result;
}

/*
 * Implementation for bind mounts
 */
static bool
__fstree_node_mount_bind(const struct fstree_node *node)
{
	const char *bind_source = node->relative_path;

	if (node->bind_mount_override_layer)
		bind_source = __pathutil_concat2(node->bind_mount_override_layer->image_path, bind_source);

	if (access(bind_source, X_OK) < 0) {
		trace("Silently ignoring system mount %s (%m)", bind_source);
		return true;
	}

	trace("Bind mounting %s on %s\n", bind_source, node->relative_path);
	switch (fsutil_get_dtype(bind_source)) {
	case DT_DIR:
		/* The mount point should be a dir already */
		break;

	case DT_LNK:
		/* leave symlinks alone */
		return true;

	default:
		if (fsutil_isdir(node->mount.mount_point)) {
			trace("  Need to change %s from dir to file", node->mount.mount_point);
			rmdir(node->mount.mount_point);
			fsutil_makefile(node->mount.mount_point, 0644);
		}
		break;
	}
	return fsutil_mount_bind(bind_source, node->mount.mount_point, true);
}

mount_ops_t	mount_ops_bind = {
	.name		= "bind",
	.mount		= __fstree_node_mount_bind,
};

/*
 * Implementation for overlay mounts
 */
static bool
__fstree_node_mount_overlay_common(const struct fstree_node *node, bool include_host_dir)
{
	char options[3 * PATH_MAX + 100];
	char *lowerspec;

	if (node->dtype >= 0 && node->dtype != DT_DIR && node->dtype != DT_REG && node->dtype != DT_LNK)
		log_warning("%s is a %s; building an overlay will probably fail",
				node->relative_path, fsutil_dtype_as_string(node->dtype));

	if (!fsutil_makedirs(node->upper, 0755)
	 || !fsutil_makedirs(node->work, 0755)
	 || !fsutil_makedirs(node->mount.mount_point, 0755))
		return false;

	if (!(lowerspec = fstree_node_build_lowerspec(node, include_host_dir)))
		return false;

	if (!(node->export_flags & FSTREE_NODE_F_READONLY))
		snprintf(options, sizeof(options),
			"userxattr,lowerdir=%s,upperdir=%s,workdir=%s",
			lowerspec, node->upper, node->work);
	else
		snprintf(options, sizeof(options),
			"userxattr,lowerdir=/%s,workdir=%s",
			lowerspec, node->work);

	trace("Mounting overlay file system on %s (options=%s)\n", node->relative_path, options);
	if (mount("wormhole", node->mount.mount_point, "overlay", MS_NOATIME|MS_LAZYTIME, options) < 0) {
		log_error("Unable to mount %s: %m\n", node->mount.mount_point);
		free(lowerspec);
		return false;
	}

	trace2("Mounted %s: %s\n", node->mount.mount_point, lowerspec);
	trace3("  mount option %s", options);

	free(lowerspec);
	return true;
}

static bool
__fstree_node_mount_overlay(const struct fstree_node *node)
{
	return __fstree_node_mount_overlay_common(node, false);
}

mount_ops_t	mount_ops_overlay = {
	.name		= "overlay",
	.mount		= __fstree_node_mount_overlay,
};

/*
 * Implementation for overlay mounts with the lowest layer being the host FS
 */
static bool
__fstree_node_mount_overlay_host(const struct fstree_node *node)
{
	return __fstree_node_mount_overlay_common(node, true);
}

mount_ops_t	mount_ops_overlay_host = {
	.name		= "host-overlay",
	.mount		= __fstree_node_mount_overlay_host,
};

/*
 * Implementation for mounts of virtual file systems
 */
static bool
__fstree_node_mount_virtual(const struct fstree_node *node)
{
	const char *fstype = node->mount_ops->name;
	const char *fsname = "wormhole";

	trace("Mounting %s file system on %s\n", fstype, node->relative_path);
	if (mount(fsname, node->mount.mount_point, fstype, MS_NOATIME|MS_LAZYTIME, NULL) < 0) {
		log_error("Unable to mount %s fs on %s: %m\n", fstype, node->mount.mount_point);
		return NULL;
	}
	return true;
}

mount_ops_t	mount_ops_tmpfs = {
	.name		= "tmpfs",
	.mount		= __fstree_node_mount_virtual,
};

/*
 * Implementation for mounts of btrfs volumes etc
 */
static bool
__fstree_node_mount_direct(const struct fstree_node *node)
{
	const char *mount_point = node->mount.mount_point;
	fsutil_mount_detail_t *detail;

	if (!(detail = node->mount.detail)) {
		log_error("direct mount: lacking fstype, device etc");
		return false;
	}

	if (!node->root) {
		log_error("direct mount: will operate only on nodes that have a fsroot set");
		return false;
	}

	trace("mounting %s below %s\n", mount_point, node->root->path);

	mount_point = __pathutil_concat2(node->root->path, mount_point);
	return fsutil_mount(detail->fsname,
			mount_point,
			detail->fstype,
			detail->options,
			detail->flags);
}

mount_ops_t	mount_ops_direct = {
	.name		= "direct",
	.mount		= __fstree_node_mount_direct,
};

/*
 * Implementation for mounts using "chroot mount ..."
 */
static bool
__fstree_node_mount_command(const struct fstree_node *node)
{
	const char *root_path, *mount_point;

	if (!node->root) {
		log_error("mountcmd: will operate only on nodes that have a fsroot set");
		return false;
	}

	root_path = node->root->path;
	mount_point = node->mount.mount_point;

	trace("mounting %s below %s\n", mount_point, root_path);
	return fsutil_mount_command(mount_point, root_path);
}

mount_ops_t	mount_ops_mountcmd = {
	.name		= "mountcmd",
	.mount		= __fstree_node_mount_command,
};

bool
fstree_node_mount(const struct fstree_node *node)
{
	if (node->mount_ops == NULL)
		return true;

	/* mount hiding - we just create the mount point but leave it unused. */
	if (node->export_type == WORMHOLE_EXPORT_HIDE)
		return true;

#if 0
	if (node->upper && chown(node->upper, 0, 0))
		log_warning("Unable to chown %s: %m", node->upper);
#endif

	if (node->parent && node->parent->export_type == WORMHOLE_EXPORT_ROOT)
		(void) fsutil_makedirs(node->mount.mount_point, 0755);

	return node->mount_ops->mount(node);
}

bool
fstree_node_traverse(struct fstree_node *node, bool (*visitorfn)(const struct fstree_node *))
{
	struct fstree_node *child;
	bool ok = true;

	if (!visitorfn(node))
		return false;

	for (child = node->children; ok && child; child = child->next)
		ok = fstree_node_traverse(child, visitorfn);

	return ok;
}

const char *
mount_export_type_as_string(int export_type)
{
	static char unknown[32];

	switch (export_type) {
	case WORMHOLE_EXPORT_ROOT:
		return "root";
	case WORMHOLE_EXPORT_AS_IS:
		return "as-is";
	case WORMHOLE_EXPORT_NONE:
		return "none";
	case WORMHOLE_EXPORT_STACKED:
		return "stacked";
	case WORMHOLE_EXPORT_TRANSPARENT:
		return "transparent";
	case WORMHOLE_EXPORT_SEMITRANSPARENT:
		return "semitransparent";
	case WORMHOLE_EXPORT_HIDE:
		return "hidden";
	case WORMHOLE_EXPORT_MOUNTIT:
		return "real";
	case WORMHOLE_EXPORT_ERROR:
		return "error";
	}

	snprintf(unknown, sizeof(unknown), "unknown (%u)", export_type);
	return unknown;
}

bool
__fstree_node_print(const struct fstree_node *node)
{
	unsigned int ws = node->depth * 2;
	const char *name = node->name;
	const char *type;

	if (!name || !*name)
		name = "/";

	type = mount_export_type_as_string(node->export_type);
	if (node->mount.mount_point) {
		trace("%*.*s%s %-12s [%s mount on %s]", ws, ws, "", name, type,
			       fstree_node_fstype(node), node->mount.mount_point);
	} else {
		trace("%*.*s%s %s", ws, ws, "", name, type);
	}
	return true;
}

void
fstree_print(struct fstree *tree)
{
	fstree_node_traverse(tree->root, __fstree_node_print);
}

/*
 * Walk a mount tree
 */
enum {
	TREE_ITER_DOWN = 0x01,
	TREE_ITER_RIGHT = 0x02,
};
struct fstree_iter {
	struct fstree_node *	current;
	struct fstree_node *	next;
	int			direction;
	bool			depth_first;
};

struct fstree_iter *
fstree_iterator_new(struct fstree *fstree, bool depth_first)
{
	struct fstree_iter *it;

	it = calloc(1, sizeof(*it));
	it->next = fstree->root;
	it->depth_first = depth_first;
	it->direction = TREE_ITER_DOWN | TREE_ITER_RIGHT;

	if (depth_first) {
		while (it->next->children)
			it->next = it->next->children;
	}

	return it;
}

static struct fstree_node *
__fstree_iterator_next(struct fstree_node *current, unsigned int dir_mask)
{
	struct fstree_node *next = current;

	while (next != NULL) {
		if ((dir_mask & TREE_ITER_DOWN) && next->children)
			return next->children;

		if ((dir_mask & TREE_ITER_RIGHT) && next->next)
			return next->next;

		/* Move up and to the right */
		dir_mask = TREE_ITER_RIGHT;
		next = next->parent;
	}

	return next;
}

static struct fstree_node *
__fstree_iterator_next_df(struct fstree_node *current)
{
	struct fstree_node *next = current;

	while (next) {
		if (next->next) {
			next = next->next;

			/* go all the way to the bottom */
			while (next->children)
				next = next->children;
			break;
		}

		return next->parent;
	}

	return next;
}

struct fstree_node *
fstree_iterator_next(struct fstree_iter *it)
{
	struct fstree_node *current = it->next;

	if (it->depth_first)
		it->next = __fstree_iterator_next_df(it->next);
	else
		it->next = __fstree_iterator_next(it->next, TREE_ITER_DOWN | TREE_ITER_RIGHT);
	it->current = current;
	return current;
}

void
fstree_iterator_skip(struct fstree_iter *it, struct fstree_node *node)
{
	if (it->depth_first)
		return;

	if (it->current == node) {
		/* Force a move up and then right */
		it->next = __fstree_iterator_next(it->current, 0);
		it->current = NULL;
	}
}

void
fstree_iterator_free(struct fstree_iter *it)
{
	free(it);
}
