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
	strutil_drop(&node->mountpoint);
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
	return node->fstype != NULL;
}

inline bool
fstree_node_is_below_mountpoint(const struct fstree_node *node)
{
	while (node) {
		if (node->fstype != NULL)
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

bool
fstree_drop_pattern(struct fstree *fstree, const char *pattern, struct strutil_array *dropped)
{
	struct pathutil_parser path_parser;
	struct fstree_node *node = NULL, **pos;

	pathutil_parser_init(&path_parser, pattern);

	/* If the path is empty, return the node itself */
	node = fstree->root;
	pos = &fstree->root;

	while (pathutil_parser_next(&path_parser)) {
		const char *name = path_parser.namebuf;

		if (!strcmp(name, "*")) {
			struct fstree_node *child = NULL;

			/* drop all children */
			while ((child = node->children) != NULL) {
				if (dropped)
					strutil_array_append(dropped, child->relative_path);
				node->children = child->next;
				fstree_node_free(child);
			}
			return true;
		}

		if (strchr(name, '*') || strchr(name, '?')) {
			log_error("%s: Cannot handle pattern \"%s\"", __func__, pattern);
			return false;
		}

		while ((node = *pos) != NULL) {
			if (!strcmp(node->name, name))
				break;
			pos = &(node->next);
		}

		if (node == NULL)
			return false;

		pos = &node->children;
	}

	if (node) {
		if (dropped)
			strutil_array_append(dropped, node->relative_path);
		*pos = node->next;
		fstree_node_free(node);
	}

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
	if (node->mountpoint)
		to_zap[i++] = node->mountpoint;

	while (i--) {
		const char *dir = to_zap[i];
		if (rmdir(dir) < 0 && errno != ENOENT) {
			if (errno != ENOTDIR || unlink(dir) < 0) {
				log_error("cannot remove %s: %m", dir);
				return false;
			}
		}
	}

	return true;
}

bool
fstree_node_set_fstype(struct fstree_node *node, const char *fstype, struct mount_farm *farm)
{
	if (node->fstype == NULL) {
		strutil_set(&node->fstype, fstype);
	} else if (strcmp(node->fstype, fstype)) {
		log_error("VFS type of %s changes from %s to %s\n", node->relative_path, node->fstype, fstype);
		return false;
	}

	if (!node->upper)
		strutil_set(&node->upper, fsutil_makedir2(farm->upper_base, node->relative_path));

	if (!node->work)
		strutil_set(&node->work, fsutil_makedir2(farm->work_base, node->relative_path));

	if (!node->mountpoint)
		strutil_set(&node->mountpoint, fsutil_makedir2(farm->chroot, node->relative_path));

	return node->upper && node->work && node->mountpoint;
}

/*
 * Change a node from a mount to in internal, non-mount node
 */
void
fstree_node_invalidate(struct fstree_node *node)
{
	if (node->export_type != WORMHOLE_EXPORT_ROOT)
		node->export_type = WORMHOLE_EXPORT_NONE;

	strutil_drop(&node->fstype);

	fstree_node_zap_dirs(node);
	strutil_drop(&node->upper);
	strutil_drop(&node->work);
	strutil_drop(&node->mountpoint);
}

char *
fstree_node_build_lowerspec(const struct fstree_node *node)
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

	result = strutil_array_join(&dirs, ":");
	strutil_array_destroy(&dirs);

	return result;
}

bool
fstree_node_mount(const struct fstree_node *node)
{
	char options[3 * PATH_MAX + 100];
	char *lowerspec;

	if (node->fstype == NULL)
		return true;

	if (!strcmp(node->fstype, "hidden")) {
		/* magic name - we just create the mount point but leave it unused. */
		return true;
	}

#if 0
	if (node->upper && chown(node->upper, 0, 0))
		log_warning("Unable to chown %s: %m", node->upper);
#endif

	if (node->parent && node->parent->export_type == WORMHOLE_EXPORT_ROOT)
		(void) fsutil_makedirs(node->mountpoint, 0755);

	if (strcmp(node->fstype, "overlay")) {
		const char *fsname = "wormhole";

		if (!strcmp(node->fstype, "bind")) {
			const char *bind_source = node->relative_path;

			if (node->bind_mount_override_layer)
				bind_source = __pathutil_concat2(node->bind_mount_override_layer->image_path, bind_source);

			trace("Bind mounting %s on %s\n", bind_source, node->relative_path);
			return fsutil_mount_bind(bind_source, node->mountpoint, true);
		}

		trace("Mounting %s file system on %s\n", node->fstype, node->relative_path);
		if (mount(fsname, node->mountpoint, node->fstype, MS_NOATIME|MS_LAZYTIME, NULL) < 0) {
			log_error("Unable to mount %s fs on %s: %m\n", node->fstype, node->mountpoint);
			return NULL;
		}
		return true;
	}

	if (node->dtype >= 0 && node->dtype != DT_REG && node->dtype != DT_LNK)
		log_warning("%s is not a regular file; building an overlay will probably fail", node->relative_path);

	if (!(lowerspec = fstree_node_build_lowerspec(node)))
		return false;

	if (!node->readonly)
		snprintf(options, sizeof(options),
			"userxattr,lowerdir=%s,upperdir=%s,workdir=%s",
			lowerspec, node->upper, node->work);
	else
		snprintf(options, sizeof(options),
			"userxattr,lowerdir=/%s,workdir=%s",
			lowerspec, node->work);

	trace("Mounting %s file system on %s (options=%s)\n", node->fstype, node->relative_path, options);
	if (mount("wormhole", node->mountpoint, "overlay", MS_NOATIME|MS_LAZYTIME, options) < 0) {
		log_error("Unable to mount %s: %m\n", node->mountpoint);
		free(lowerspec);
		return NULL;
	}

	trace2("Mounted %s: %s\n", node->mountpoint, lowerspec);
	trace3("  mount option %s", options);

	free(lowerspec);
	return node;
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
	switch (export_type) {
	case WORMHOLE_EXPORT_ROOT:
		return "root";
	case WORMHOLE_EXPORT_NONE:
		return "none";
	case WORMHOLE_EXPORT_STACKED:
		return "stacked";
	case WORMHOLE_EXPORT_TRANSPARENT:
		return "transparent";
	case WORMHOLE_EXPORT_ERROR:
		return "error";
	}

	return "unknown";
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
	if (node->mountpoint) {
		trace("%*.*s%s %-12s [%s mount on %s]", ws, ws, "", name, type, node->fstype, node->mountpoint);
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
