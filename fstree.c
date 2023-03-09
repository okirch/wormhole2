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
#include <assert.h>

#include "wormhole2.h"
#include "paths.h"
#include "tracing.h"
#include "util.h"


struct mount_state *
mount_state_new(void)
{
	struct mount_state *state;

	state = calloc(1, sizeof(*state));
	state->root = mount_leaf_new("", "/");

	return state;
}

void
mount_state_free(struct mount_state *state)
{
	struct mount_leaf *root;

	if ((root = state->root) != NULL) {
		mount_leaf_free(root);
		state->root = NULL;
	}
}

struct mount_leaf *
mount_state_create_leaf(struct mount_state *state, const char *relative_path)
{
	return mount_leaf_lookup(state->root, relative_path, true);
}

static bool
__mount_state_make_relative_paths(struct mount_leaf *leaf, const char *common_root, unsigned int len)
{
	struct mount_leaf *child;
	bool okay = true;

	if (memcmp(leaf->relative_path, common_root, len))
		goto bad_path;

	if (leaf->relative_path[len] == '\0')
		strutil_set(&leaf->relative_path, "/");
	else
	if (leaf->relative_path[len] != '/')
		goto bad_path;
	else
		strutil_set(&leaf->relative_path, leaf->relative_path + len);

	// trace(" %s -> %s", leaf->full_path, leaf->relative_path);
	for (child = leaf->children; okay && child; child = child->next)
		okay = __mount_state_make_relative_paths(child, common_root, len);

	return okay;

bad_path:
	log_error("%s is not relative to %s\n", leaf->relative_path, common_root);
	return false;
}

bool
mount_state_make_relative(struct mount_state *state, const char *common_root)
{
	struct mount_leaf *layer_root;

	layer_root = mount_leaf_lookup(state->root, common_root, false);
	if (!layer_root)
		return false;

	if (!__mount_state_make_relative_paths(layer_root, common_root, strlen(common_root)))
		return false;

	/* XXX: we leak some memory here */
	state->root = layer_root;
	return true;
}

void
mount_leaf_free(struct mount_leaf *leaf)
{
	struct mount_leaf *child;

	leaf->parent = NULL;

	while ((child = leaf->children) != NULL) {
		leaf->children = child->next;
		mount_leaf_free(child);
	}

	strutil_drop(&leaf->relative_path);
	strutil_drop(&leaf->full_path);
	strutil_drop(&leaf->upper);
	strutil_drop(&leaf->work);
	strutil_drop(&leaf->mountpoint);
}

struct mount_leaf *
mount_leaf_new(const char *name, const char *relative_path)
{
	struct mount_leaf *leaf;

	leaf = calloc(1, sizeof(*leaf));
	leaf->name = strdup(name);
	leaf->relative_path = strdup(relative_path);
	leaf->full_path = strdup(relative_path);

	return leaf;
}

inline bool
mount_leaf_is_mountpoint(const struct mount_leaf *leaf)
{
	return leaf->fstype != NULL;
}

inline bool
mount_leaf_is_below_mountpoint(const struct mount_leaf *leaf)
{
	while (leaf) {
		if (leaf->fstype != NULL)
			return true;
		leaf = leaf->parent;
	}
	return false;
}

struct mount_leaf *
mount_leaf_lookup(struct mount_leaf *parent, const char *relative_path, bool create)
{
	struct pathutil_parser path_parser;
	struct mount_leaf *leaf = NULL, **pos;

	pathutil_parser_init(&path_parser, relative_path);

	/* If the path is empty, return the node itself */
	leaf = parent;

	pos = &parent->children;

	while (pathutil_parser_next(&path_parser)) {
		const char *name = path_parser.namebuf;

		while ((leaf = *pos) != NULL) {
			if (!strcmp(leaf->name, name))
				break;
			pos = &(leaf->next);
		}

		if (leaf == NULL) {
			if (!create)
				break;

			// trace3("Creating node for %s as child of %s\n", path_parser.pathbuf, parent->relative_path);
			leaf = mount_leaf_new(path_parser.namebuf, path_parser.pathbuf);
			leaf->depth = parent->depth + 1;

			leaf->parent = parent;
			*pos = leaf;
		}

		parent = leaf;
		pos = &leaf->children;
	}

	return leaf;
}

bool
mount_leaf_set_fstype(struct mount_leaf *leaf, const char *fstype, struct mount_farm *farm)
{
	if (leaf->fstype == NULL) {
		strutil_set(&leaf->fstype, fstype);
	} else if (strcmp(leaf->fstype, fstype)) {
		log_error("VFS type of %s changes from %s to %s\n", leaf->relative_path, leaf->fstype, fstype);
		return false;
	}

	if (!leaf->upper)
		strutil_set(&leaf->upper, fsutil_makedir2(farm->upper_base, leaf->relative_path));

	if (!leaf->work)
		strutil_set(&leaf->work, fsutil_makedir2(farm->work_base, leaf->relative_path));

	if (!leaf->mountpoint)
		strutil_set(&leaf->mountpoint, fsutil_makedir2(farm->chroot, leaf->relative_path));

	return leaf->upper && leaf->work && leaf->mountpoint;
}

bool
mount_leaf_add_lower(struct mount_leaf *leaf, const char *path)
{
	unsigned int n;

	if (leaf->fstype == NULL || strcmp(leaf->fstype, "overlay")) {
		log_error("Cannot add lowerdir %s to %s - not configured as overlay mount",
				path, leaf->relative_path);
		return false;
	}

	/* avoid duplicates */
	for (n = 0; n < leaf->nlower; ++n) {
		if (!strcmp(leaf->lower[n], path))
			return true;
	}

	if (leaf->nlower >= MOUNT_LEAF_LOWER_MAX) {
		log_error("%s: too many lower mounts\n", leaf->relative_path);
		return false;
	}

	trace("%s: adding lowerdir %s\n", leaf->relative_path, path);
	assert(strncmp(path, "/tmp/wormhole", 13));
	leaf->lower[leaf->nlower++] = strdup(path);
	return true;
}

char *
mount_leaf_build_lowerspec(const struct mount_leaf *leaf)
{
	const unsigned int bufsz = 8192;
	char *lowerspec;
	unsigned int n, wpos;

	lowerspec = malloc(bufsz);
	for (n = 0, wpos = 0; n < leaf->nlower; ++n) {
		const char *lower = leaf->lower[n];
		unsigned int lower_len;

		if (wpos != 0)
			lowerspec[wpos++] = ':';

		lower_len = strlen(lower);
		if (wpos + lower_len >= bufsz) {
			log_error("Too many names in lowerdir spec at %s\n", leaf->relative_path);
			return false;
		}

		memcpy(lowerspec + wpos, lower, lower_len);
		wpos += lower_len;
	}

	lowerspec[wpos++] = '\0';
	return lowerspec;
}

bool
mount_leaf_mount(const struct mount_leaf *leaf)
{
	char options[3 * PATH_MAX + 100];
	char *lowerspec;

	if (leaf->fstype == NULL)
		return true;

	if (!strcmp(leaf->fstype, "hidden")) {
		/* magic name - we just create the mount point but leave it unused. */
		return true;
	}

	if (chown(leaf->upper, 0, 0))
		log_warning("Unable to chown %s: %m", leaf->upper);

	if (strcmp(leaf->fstype, "overlay")) {
		trace("Mounting %s file system on %s\n", leaf->fstype, leaf->relative_path);
		if (mount("wormhole", leaf->mountpoint, leaf->fstype, MS_NOATIME|MS_LAZYTIME, NULL) < 0) {
			log_error("Unable to mount %s fs on %s: %m\n", leaf->fstype, leaf->mountpoint);
			return NULL;
		}
		return true;
	}

	if (leaf->nlower == 0)
		return true;

	if (!(lowerspec = mount_leaf_build_lowerspec(leaf)))
		return false;

	if (!leaf->readonly)
		snprintf(options, sizeof(options),
			"lowerdir=%s,upperdir=%s,workdir=%s",
			lowerspec, leaf->upper, leaf->work);
	else
		snprintf(options, sizeof(options),
			"lowerdir=/%s,workdir=%s",
			lowerspec, leaf->work);

	trace("Mounting %s file system on %s (lower=%s)\n", leaf->fstype, leaf->relative_path, lowerspec);
	if (mount("wormhole", leaf->mountpoint, "overlay", MS_NOATIME|MS_LAZYTIME, options) < 0) {
		log_error("Unable to mount %s: %m\n", leaf->mountpoint);
		free(lowerspec);
		return NULL;
	}

	trace2("Mounted %s: %s\n", leaf->mountpoint, lowerspec);
	trace3("  mount option %s", options);

	free(lowerspec);
	return leaf;
}

bool
mount_leaf_traverse(struct mount_leaf *node, bool (*visitorfn)(const struct mount_leaf *))
{
	struct mount_leaf *leaf;
	bool ok = true;

	if (!visitorfn(node))
		return false;

	for (leaf = node->children; ok && leaf; leaf = leaf->next)
		ok = mount_leaf_traverse(leaf, visitorfn);

	return ok;
}

bool
__mount_leaf_print(const struct mount_leaf *leaf)
{
	unsigned int ws = leaf->depth * 2;
	const char *name = leaf->name;

	if (!name || !*name)
		name = "/";

	if (leaf->mountpoint) {
		trace("%*.*s%s [%s mount on %s]", ws, ws, "", name, leaf->fstype, leaf->mountpoint);
	} else {
		trace("%*.*s%s", ws, ws, "", name);
	}
	return true;
}

void
mount_tree_print(struct mount_leaf *leaf)
{
	mount_leaf_traverse(leaf, __mount_leaf_print);
}

