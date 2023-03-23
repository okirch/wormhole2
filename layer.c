/*
 * wormhole layers
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "wormhole2.h"
#include "paths.h"
#include "tracing.h"
#include "util.h"

static char *	wormhole_layer_make_user_path(const char *name);

struct wormhole_layer *
wormhole_layer_new(const char *name, const char *path, unsigned int depth)
{
	struct wormhole_layer *layer;

	layer = calloc(1, sizeof(*layer));
	layer->refcount = 1;
	layer->name = strdup(name);
	layer->depth = depth;

	if (path) {
		strutil_set(&layer->path, path);
	} else {
		char *user_path = wormhole_layer_make_user_path(name);

		/* FIXME: more consistency checks? */
		if (user_path && fsutil_isdir(user_path))
			strutil_set(&layer->path, user_path);
		else
			pathutil_concat2(&layer->path, WORMHOLE_LAYER_BASE_PATH, name);

		strutil_drop(&user_path);
	}

	pathutil_concat2(&layer->config_path, layer->path, "layer.conf");
	pathutil_concat2(&layer->image_path, layer->path, "image");
	pathutil_concat2(&layer->wrapper_path, layer->path, "bin");
	pathutil_concat2(&layer->rpmdb_path, layer->path, "rpm.patch");

	return layer;
}

static void
wormhole_layer_free(struct wormhole_layer *layer)
{
	assert(layer->refcount == 0);
	strutil_set(&layer->name, NULL);
	strutil_set(&layer->path, NULL);
	strutil_set(&layer->image_path, NULL);
	strutil_set(&layer->wrapper_path, NULL);
	strutil_set(&layer->rpmdb_path, NULL);
	mount_config_array_destroy(&layer->stacked_directories);
	mount_config_array_destroy(&layer->transparent_directories);
	strutil_array_destroy(&layer->entry_points);
	strutil_mapping_destroy(&layer->entry_point_symlinks);

	free(layer);
}

struct wormhole_layer *
wormhole_layer_hold(struct wormhole_layer *layer)
{
	assert(layer->refcount);
	layer->refcount += 1;
	return layer;
}

void
wormhole_layer_release(struct wormhole_layer *layer)
{
	assert(layer->refcount);
	if (--(layer->refcount) == 0)
		wormhole_layer_free(layer);
}

void
wormhole_layer_array_append(struct wormhole_layer_array *a, struct wormhole_layer *layer)
{
	if ((a->count & 15) == 0) {
		a->data = realloc(a->data, (a->count + 16) * sizeof(a->data[0]));
	}

	a->data[a->count++] = wormhole_layer_hold(layer);
}

void
wormhole_layer_array_append_unique(struct wormhole_layer_array *a, struct wormhole_layer *layer)
{
	unsigned int i;

	for (i = 0; i < a->count; ++i) {
		if (a->data[i] == layer)
			return;
	}

	wormhole_layer_array_append(a, layer);
}


struct wormhole_layer *
wormhole_layer_array_find(struct wormhole_layer_array *a, const char *name)
{
	struct wormhole_layer *layer;
	unsigned int i;

	for (i = 0; i < a->count; ++i) {
		layer = a->data[i];
		if (!strcmp(layer->name, name))
			return layer;
	}

	return NULL;
}

void
wormhole_layer_array_destroy(struct wormhole_layer_array *a)
{
	unsigned int i;

	for (i = 0; i < a->count; ++i)
		wormhole_layer_release(a->data[i]);

	if (a->data)
		free(a->data);
	memset(a, 0, sizeof(*a));
}

bool
__parse_boolean(const char *path, unsigned int line, const char *value, bool *ret)
{
	if (!strcasecmp(value, "true") || !strcasecmp(value, "yes")) {
		*ret = true;
		return true;
	}
	if (!strcasecmp(value, "false") || !strcasecmp(value, "no")) {
		*ret = false;
		return true;
	}

	log_error("%s:%u: invalid boolean value \"%s\"", value);
	return false;
}

static bool
__parse_mount(struct mount_config_array *a, const char *kwd, char *value, int dtype)
{
	return !!mount_config_array_add(a, value, dtype);
}

bool
wormhole_layer_load_config(struct wormhole_layer *layer)
{
	char linebuf[256];
	unsigned int line = 0;
	bool okay = true;
	FILE *fp;

	if (!(fp = fopen(layer->config_path, "r"))) {
		if (errno == ENOENT) {
			trace("%s: no config file at %s", layer->name, layer->config_path);
			return true;
		}

		log_error("%s: %m", layer->config_path);
		return false;
	}

	while (fgets(linebuf, sizeof(linebuf), fp) != NULL) {
		char *kwd, *value;

		++line;
		if (linebuf[0] == '#')
			continue;
		linebuf[strcspn(linebuf, "\n")] = '\0';

		if (!(kwd = strtok(linebuf, "=")))
			continue;
		if (!(value = strtok(NULL, "")))
			value = "";

		if (!strcmp(kwd, "is-root")) {
			okay = __parse_boolean(layer->config_path, line, value, &layer->is_root);
		} else
		if (!strcmp(kwd, "use-layer")) {
			strutil_array_append(&layer->used, value);
		} else
		if (!strcmp(kwd, "stacked-mount")) {
			okay = __parse_mount(&layer->stacked_directories, kwd, value, DT_DIR);
		} else
		if (!strcmp(kwd, "transparent-mount")) {
			okay = __parse_mount(&layer->transparent_directories, kwd, value, DT_DIR);
		} else
		if (!strcmp(kwd, "transparent-file-mount")) {
			okay = __parse_mount(&layer->transparent_directories, kwd, value, DT_REG);
		} else {
			log_error("%s:%u: unsupported directive %s=%s",
					layer->config_path, line,
					kwd, value);
			okay = false;
		}
	}

	fclose(fp);
	return okay;
}

bool
wormhole_layer_save_config(struct wormhole_layer *layer)
{
	unsigned int i;
	FILE *fp;

	if (!(fp = fopen(layer->config_path, "w"))) {
		log_error("%s: %m", layer->config_path);
		return false;
	}

	fprintf(fp, "# Automatically generated by wormhole build\n");

	if (layer->is_root)
		fprintf(fp, "is-root=true\n");
	for (i = 0; i < layer->used.count; ++i)
		fprintf(fp, "use-layer=%s\n", layer->used.data[i]);
	for (i = 0; i < layer->stacked_directories.count; ++i) {
		struct mount_config *mnt = layer->stacked_directories.data[i];

		if (mnt->dtype != DT_DIR) {
			log_error("%s: bad dtype %u for %s", __func__, mnt->dtype, mnt->path);
			return false;
		}
		fprintf(fp, "stacked-mount=%s\n", mnt->path);
	}
	for (i = 0; i < layer->transparent_directories.count; ++i) {
		struct mount_config *mnt = layer->transparent_directories.data[i];
		const char *kwd = NULL;

		if (mnt->dtype == DT_DIR) {
			kwd = "transparent-mount";
		} else
		if (mnt->dtype == DT_REG) {
			kwd = "transparent-file-mount";
		} else {
			log_error("%s: bad dtype %u for %s", __func__, mnt->dtype, mnt->path);
			return false;
		}
		fprintf(fp, "%s=%s\n", kwd, mnt->path);
	}

	fclose(fp);
	return true;
}

/*
 * For a given entry point, create a wrapper scripts
 */
static bool
wormhole_layer_write_wrapper(struct wormhole_layer *layer, const char *app_path, const char *install_bindir)
{
	char *wrapper_path = NULL;
	bool ok = false;
	FILE *fp;

	trace("Creating wrapper script for %s", app_path);
	if (!fsutil_makedirs(layer->wrapper_path, 0755))
		goto out;

	pathutil_concat2(&wrapper_path, layer->wrapper_path, basename(app_path));
	if (!(fp = fopen(wrapper_path, "w"))) {
		log_error("%s: %m", wrapper_path);
		goto out;
	}

	fprintf(fp, "#!/bin/bash\n");
	fprintf(fp, "exec /usr/bin/wormhole -L \"%s\" -- %s \"$@\"\n",
			layer->name, app_path);

	fclose(fp);

	if (chmod(wrapper_path, 0555) < 0) {
		log_error("cannot chmod %s: %m", wrapper_path);
		goto out;
	}

	ok = true;

out:
	strutil_drop(&wrapper_path);
	return ok;
}

bool
wormhole_layer_create_default_wrapper_symlinks(struct wormhole_layer *layer)
{
	unsigned int i;

	for (i = 0; i < layer->entry_points.count; ++i) {
		const char *name = basename(layer->entry_points.data[i]);

		strutil_mapping_add_no_override(&layer->entry_point_symlinks, name, name);
	}
	return true;
}

bool
wormhole_layer_write_wrappers(struct wormhole_layer *layer, const char *install_bindir)
{
	unsigned int i;
	bool ok = true;

	trace("=== Creating wrapper scripts ===");
	for (i = 0; i < layer->entry_points.count; ++i) {
		const char *app_path = layer->entry_points.data[i];

		if (!wormhole_layer_write_wrapper(layer, app_path, install_bindir))
			ok = false;
	}

	if (install_bindir) {
		char *symlink_path = NULL, *wrapper_path = NULL;

		for (i = 0; i < layer->entry_point_symlinks.count; ++i) {
			struct strutil_mapping_pair *entry = &layer->entry_point_symlinks.data[i];

			pathutil_concat2(&wrapper_path, layer->wrapper_path, entry->key);

			if (entry->value == NULL)
				continue;

			if (entry->value[0] == '/')
				strutil_set(&symlink_path, entry->value);
			else
				pathutil_concat2(&symlink_path, install_bindir, entry->value);

			trace("  install symlink %s -> %s", symlink_path, wrapper_path);
			(void) unlink(symlink_path);
			if (symlink(wrapper_path, symlink_path) < 0) {
				log_error("Cannot create symlink %s -> %s: %m", symlink_path, wrapper_path);
				ok = false;
			}
		}
	}

	return ok;
}

void
wormhole_layer_add_entry_point_symlink(struct wormhole_layer *layer, const char *entry_point_name, const char *symlink_path)
{
	strutil_mapping_add(&layer->entry_point_symlinks, entry_point_name, symlink_path);
}

/*
 * Remount /usr/lib/platform/layers/foobar to some tmpfs to shorten the path.
 */
bool
wormhole_layer_remount_image(struct wormhole_layer *layer, const char *image_base)
{
	static char layer_bind_path[PATH_MAX];

	snprintf(layer_bind_path, sizeof(layer_bind_path), "%s/%s/image", image_base, layer->name);
	if (!fsutil_makedirs(layer_bind_path, 0755)) {
		log_error("Unable to create %s: %m\n", layer_bind_path);
		return false;
	}

	trace("Remounting %s as %s", layer->image_path, layer_bind_path);
	if (!fsutil_mount_bind(layer->image_path, layer_bind_path, false))
		return false;

	strutil_set(&layer->image_path, layer_bind_path);
	return true;
}

/*
 * For a given layer, find the layers it requires and load them
 */
static bool
__wormhole_layers_resolve(struct wormhole_layer_array *layers, const char *name, unsigned int depth, const char *remount_image_base)
{
	struct wormhole_layer *layer = NULL;
	bool okay = false;
	unsigned int i;

	if (depth > 100) {
		log_error("too many nested layers, possibly a circular reference");
		return false;
	}

	if (wormhole_layer_array_find(layers, name))
		return true;

	layer = wormhole_layer_new(name, NULL, depth);

	if (remount_image_base && !wormhole_layer_remount_image(layer, remount_image_base))
		goto failed;

	if (!wormhole_layer_load_config(layer))
		goto failed;

	/* Now resolve the lower layers referenced by this one */
	for (i = 0; i < layer->used.count; ++i) {
		if (!__wormhole_layers_resolve(layers, layer->used.data[i], depth + 1, remount_image_base))
			goto failed;
	}

	wormhole_layer_array_append(layers, layer);
	okay = true;

failed:
	if (layer)
		wormhole_layer_release(layer);
	return okay;
}

bool
wormhole_layers_resolve(struct wormhole_layer_array *layers, const struct strutil_array *names, const char *remount_image_base)
{
	unsigned int i;

	trace2("%s()", __func__);
	for (i = 0; i < names->count; ++i) {
		const char *name = names->data[i];

		if (!__wormhole_layers_resolve(layers, name, 0, remount_image_base))
			return false;
	}

	if (layers->count == 0 || !layers->data[0]->is_root) {
		log_error("Refusing to run without a root layer");
		return false;
	}

	for (i = 1; i < layers->count; ++i) {
		if (layers->data[i]->is_root) {
			log_error("Misconfiguration - cannot run with two different root layers (%s and %s)",
					layers->data[0]->name,
					layers->data[i]->name);
			return false;
		}
	}

	trace("configured %u layers", layers->count);
	return true;
}


bool
wormhole_layer_update_from_mount_farm(struct wormhole_layer *layer, const struct fstree_node *tree)
{
	const struct fstree_node *child;
	bool okay = true;

	if (tree->export_type == WORMHOLE_EXPORT_ROOT) {
		/* nothing to be done */
	} else
	if (tree->export_type == WORMHOLE_EXPORT_STACKED) {
		okay = mount_config_array_add(&layer->stacked_directories, tree->relative_path, tree->dtype);
	} else
	if (tree->export_type == WORMHOLE_EXPORT_TRANSPARENT) {
		okay = mount_config_array_add(&layer->transparent_directories, tree->relative_path, tree->dtype);
	} else
	if (tree->export_type != WORMHOLE_EXPORT_NONE) {
		log_error("%s: bad export type %u at %s", __func__, tree->export_type, tree->relative_path);
		return false;
	}

	for (child = tree->children; child; child = child->next) {
		if (!wormhole_layer_update_from_mount_farm(layer, child))
			return false;
	}

	return okay;
}

bool
wormhole_layer_build_mount_farm(struct wormhole_layer *layer, struct mount_farm *farm)
{
	struct fstree_node *new_mount;
	unsigned int i;

	for (i = 0; i < layer->stacked_directories.count; ++i) {
		struct mount_config *mnt = layer->stacked_directories.data[i];

		if (!(new_mount = mount_farm_add_stacked(farm, mnt->path, layer)))
			return false;
		fstree_node_set_fstype(new_mount, "overlay", farm);
	}

	for (i = 0; i < layer->transparent_directories.count; ++i) {
		struct mount_config *mnt = layer->transparent_directories.data[i];

		if (!(new_mount = mount_farm_add_transparent(farm, mnt->path, mnt->dtype, layer)))
			return false;
		fstree_node_set_fstype(new_mount, "bind", farm);
	}

	return true;
}

/*
 * Given a layer name, build the path name to the user-private layer directory
 */
static char *
wormhole_layer_make_user_path(const char *name)
{
	char pathbuf[PATH_MAX];

	snprintf(pathbuf, sizeof(pathbuf), "%s/%s", WORMHOLE_USER_LAYER_BASE_PATH, name);
	return pathutil_expand(pathbuf, false);
}

static char *
wormhole_layer_make_system_path(const char *name)
{
	char *result = NULL;

	pathutil_concat2(&result, WORMHOLE_LAYER_BASE_PATH, name);
	return result;
}

char *
wormhole_layer_make_path(const char *target_name, int target_type)
{
	if (target_type == BUILD_USER_LAYER)
		return wormhole_layer_make_user_path(target_name);
	return wormhole_layer_make_system_path(target_name);
}
