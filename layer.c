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

static struct strutil_array	layer_search_path;
static const char *		layer_type_names[__LAYER_TYPE_MAX] = {
	[LAYER_TYPE_USER]	= "user",
	[LAYER_TYPE_SITE]	= "site",
	[LAYER_TYPE_SYSTEM]	= "system",
};

static struct {
	char *			path[__LAYER_TYPE_MAX];
} layer_defaults;

/*
 * Configure the search path for wormhole layers
 */
void
wormhole_layer_add_search_path(int layer_type, const char *path)
{
	char **var = NULL;
	char *expanded_path;

	expanded_path = pathutil_expand(path, false);

	if (layer_type == LAYER_TYPE_USER || fsutil_isdir(expanded_path)) {
		if (0 <= layer_type && layer_type < __LAYER_TYPE_MAX)
			var = &layer_defaults.path[layer_type];
		if (var && *var == NULL)
			strutil_set(var, expanded_path);

		strutil_array_append(&layer_search_path, expanded_path);
	}

	strutil_drop(&expanded_path);
}

void
wormhole_layer_set_default_search_path(void)
{
	if (layer_search_path.count)
		return;

	wormhole_layer_add_search_path(LAYER_TYPE_USER, WORMHOLE_USER_LAYER_BASE_PATH);
	wormhole_layer_add_search_path(LAYER_TYPE_SITE, WORMHOLE_SITE_LAYER_BASE_PATH);
	wormhole_layer_add_search_path(LAYER_TYPE_SYSTEM, WORMHOLE_LAYER_BASE_PATH);
}

void
wormhole_layer_print_default_search_path(void)
{
	unsigned int i, j;

	trace("Search path:");
	for (i = 0; i < layer_search_path.count; ++i) {
		const char *layer_base = layer_search_path.data[i];
		const char *type = NULL;

		for (j = 0; j < __LAYER_TYPE_MAX; ++j) {
			const char *def_base = layer_defaults.path[j];

			if (def_base && !strcmp(def_base, layer_base))
				type = layer_type_names[j];
		}

		if (type)
			trace("  %s [%s]", layer_base, type);
		else
			trace("  %s", layer_search_path.data[i]);
	}
}

/*
 * Handle layer configuration object
 */
bool
wormhole_layer_config_use_system_root(const struct wormhole_layer_config *layercfg)
{
	struct wormhole_layer *root_layer;

	if (layercfg->array.count == 0)
		return false;

	root_layer = layercfg->array.data[0];
	return strutil_equal(root_layer->image_path, "/");
}

int
wormhole_layer_config_base_layer_type(const struct wormhole_layer_config *layercfg)
{
	if (wormhole_layer_config_use_system_root(layercfg))
		return WORMHOLE_BASE_LAYER_HOST;
	return WORMHOLE_BASE_LAYER_CONTAINER;
}

/*
 * Create a new layer object. Try to locate the layer image and config.
 */
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
		unsigned int i;

		/* In case the caller missed it */
		wormhole_layer_set_default_search_path();

		for (i = 0; i < layer_search_path.count; ++i) {
			char *layer_path = NULL;

			pathutil_concat2(&layer_path, layer_search_path.data[i], name);

			/* FIXME: In addition to checking whether the directory exists, we should
			 * probably also check for the existence of a layer.conf file */
			if (fsutil_isdir(layer_path)) {
				layer->path = layer_path;
				break;
			}

			strutil_drop(&layer_path);
		}

		if (layer->path == NULL) {
			log_error("Cannot find a definition for layer \"%s\"", name);
			wormhole_layer_release(layer);
			return NULL;
		}
	}

	pathutil_concat2(&layer->config_path, layer->path, "layer.conf");
	pathutil_concat2(&layer->image_path, layer->path, "image");
	pathutil_concat2(&layer->wrapper_path, layer->path, "bin");
	pathutil_concat2(&layer->rpmdb_path, layer->path, "rpm.patch");

	return layer;
}

struct wormhole_layer *
__wormhole_layer_new(const char *name)
{
	struct wormhole_layer *layer;

	layer = calloc(1, sizeof(*layer));
	layer->refcount = 1;
	layer->name = strdup(name);
	layer->depth = 0;

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
	mount_config_array_destroy(&layer->mounts);
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
wormhole_layer_array_prepend(struct wormhole_layer_array *a, struct wormhole_layer *layer)
{
	if ((a->count & 15) == 0) {
		a->data = realloc(a->data, (a->count + 16) * sizeof(a->data[0]));
	}

	memmove(a->data + 1, a->data, a->count * sizeof(a->data[0]));
	a->data[0] = wormhole_layer_hold(layer);
	a->count += 1;
}

static inline bool
wormhole_layer_has(const struct wormhole_layer_array *a, const struct wormhole_layer *layer)
{
	unsigned int i;

	for (i = 0; i < a->count; ++i) {
		if (a->data[i] == layer)
			return true;
	}

	return false;
}

void
wormhole_layer_array_append_unique(struct wormhole_layer_array *a, struct wormhole_layer *layer)
{
	if (!wormhole_layer_has(a, layer))
		wormhole_layer_array_append(a, layer);
}

void
wormhole_layer_array_prepend_unique(struct wormhole_layer_array *a, struct wormhole_layer *layer)
{
	if (!wormhole_layer_has(a, layer))
		wormhole_layer_array_prepend(a, layer);
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
__parse_mount(struct mount_config_array *a, const char *kwd, char *value, int dtype,
		mount_origin_t mode, mount_origin_t origin)
{
	return !!mount_config_array_add(a, value, dtype, mode, origin);
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
		if (!strcmp(kwd, "image-root")) {
			strutil_set(&layer->image_path, value);
		} else
		if (!strcmp(kwd, "use-layer")) {
			strutil_array_append(&layer->used, value);
		} else
		if (!strcmp(kwd, "stacked-mount")) {
			okay = __parse_mount(&layer->mounts, kwd, value, DT_DIR,
					MOUNT_ORIGIN_LAYER, MOUNT_MODE_OVERLAY);
		} else
		if (!strcmp(kwd, "transparent-mount")) {
			okay = __parse_mount(&layer->mounts, kwd, value, DT_DIR,
					MOUNT_ORIGIN_SYSTEM, MOUNT_MODE_BIND);
		} else
		if (!strcmp(kwd, "semitransparent-mount")) {
			okay = __parse_mount(&layer->mounts, kwd, value, DT_DIR,
					MOUNT_ORIGIN_SYSTEM, MOUNT_MODE_OVERLAY);
		} else
		if (!strcmp(kwd, "transparent-file-mount")) {
			okay = __parse_mount(&layer->mounts, kwd, value, DT_REG,
					MOUNT_ORIGIN_SYSTEM, MOUNT_MODE_BIND);
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

	fprintf(fp, "image-root=%s\n", layer->image_path);
	if (layer->is_root)
		fprintf(fp, "is-root=true\n");
	for (i = 0; i < layer->used.count; ++i)
		fprintf(fp, "use-layer=%s\n", layer->used.data[i]);

	for (i = 0; i < layer->mounts.count; ++i) {
		struct mount_config *mnt = layer->mounts.data[i];
		const char *kwd = NULL;

		if (mnt->origin == MOUNT_ORIGIN_LAYER && mnt->mode == MOUNT_MODE_OVERLAY) {
			if (mnt->dtype == DT_DIR)
				kwd = "stacked-mount";
		} else
		if (mnt->origin == MOUNT_ORIGIN_SYSTEM && mnt->mode == MOUNT_MODE_OVERLAY) {
			if (mnt->dtype == DT_DIR)
				kwd = "semitransparent-mount";
		} else
		if (mnt->origin == MOUNT_ORIGIN_SYSTEM && mnt->mode == MOUNT_MODE_BIND) {
			if (mnt->dtype == DT_DIR)
				kwd = "transparent-mount";
			else
			if (mnt->dtype == DT_REG)
				kwd = "transparent-file-mount";
		} else {
			log_error("%s: unsupported origin/mode combination for %s", __func__, mnt->path);
			return false;
		}

		if (kwd == NULL) {
			log_error("%s: cannot add %s %s to overlay (not supported)", __func__, fsutil_dtype_as_string(mnt->dtype), mnt->path);
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

	/* Do not remount the image layer if the resulting path would be longer. */
	if (strlen(layer_bind_path) >= strlen(layer->image_path))
		return true;

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
__wormhole_layers_resolve(struct wormhole_layer_config *layercfg, const char *name, unsigned int depth)
{
	struct wormhole_layer *layer = NULL;
	bool okay = false;
	unsigned int i;

	if (depth > 100) {
		log_error("too many nested layers, possibly a circular reference");
		return false;
	}

	if (wormhole_layer_array_find(&layercfg->array, name))
		return true;

	layer = wormhole_layer_new(name, NULL, depth);

	if (!wormhole_layer_load_config(layer))
		goto failed;

	/* Now resolve the lower layers referenced by this one */
	for (i = 0; i < layer->used.count; ++i) {
		if (!__wormhole_layers_resolve(layercfg, layer->used.data[i], depth + 1))
			goto failed;
	}

	wormhole_layer_array_append(&layercfg->array, layer);
	okay = true;

failed:
	if (layer)
		wormhole_layer_release(layer);
	return okay;
}

bool
wormhole_layers_resolve(struct wormhole_layer_config *layercfg)
{
	struct wormhole_layer *root_layer;
	unsigned int i;

	trace2("%s()", __func__);
	for (i = 0; i < layercfg->names.count; ++i) {
		const char *name = layercfg->names.data[i];

		if (!__wormhole_layers_resolve(layercfg, name, 0))
			return false;
	}

	if (layercfg->array.count == 0)
		goto missing_root_layer;

	root_layer = layercfg->array.data[0];
	if (!root_layer->is_root)
		goto missing_root_layer;

	for (i = 1; i < layercfg->array.count; ++i) {
		if (layercfg->array.data[i]->is_root) {
			log_error("Misconfiguration - cannot run with two different root layers (%s and %s)",
					layercfg->array.data[0]->name,
					layercfg->array.data[i]->name);
			return false;
		}
	}

	trace("configured %u layers", layercfg->array.count);
	return true;

missing_root_layer:
	log_error("Refusing to run without a root layer");
	return false;
}

bool
wormhole_layers_remount(struct wormhole_layer_config *layercfg)
{
	unsigned int i;

	trace2("%s()", __func__);
	if (layercfg->remount_image_base == NULL) {
		log_error("%s: remount base path is NULL", __func__);
		return false;
	}

	for (i = 0; i < layercfg->array.count; ++i) {
		struct wormhole_layer *layer = layercfg->array.data[i];

		if (!wormhole_layer_remount_image(layer, layercfg->remount_image_base))
			return false;
	}

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
		okay = mount_config_array_add(&layer->mounts, tree->relative_path, tree->dtype,
				MOUNT_ORIGIN_LAYER, MOUNT_MODE_OVERLAY);
	} else
	if (tree->export_type == WORMHOLE_EXPORT_TRANSPARENT) {
		okay = mount_config_array_add(&layer->mounts, tree->relative_path, tree->dtype,
				MOUNT_ORIGIN_SYSTEM, MOUNT_MODE_BIND);
	} else
	if (tree->export_type == WORMHOLE_EXPORT_SEMITRANSPARENT) {
		okay = mount_config_array_add(&layer->mounts, tree->relative_path, tree->dtype,
				MOUNT_ORIGIN_SYSTEM, MOUNT_MODE_OVERLAY);
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

	for (i = 0; i < layer->mounts.count; ++i) {
		struct mount_config *mnt = layer->mounts.data[i];

		if (!(new_mount = mount_farm_add_mount(farm, mnt, layer)))
			return false;
	}

	return true;
}

/*
 * When building a user layer as non-root user, we need to pretend to that all
 * system directories are writable. We do this by creating a copy of each 
 * directory node in the upperdir layer, giving it the correct permissions,
 * and above all, making it owned by the invoking user.
 */
bool
wormhole_layer_copyup_directories(const struct wormhole_layer *layer, const char *upperdir,
		struct strutil_array *dir_list)
{
	struct fsutil_ftw_ctx *ftw;
	struct fsutil_ftw_cursor cursor;
	const struct dirent *d;

	trace(" %s -> %s", layer->image_path, upperdir);

	if (!(ftw = fsutil_ftw_open("/", FSUTIL_FTW_NEED_STAT, layer->image_path)))
		return true;

	while ((d = fsutil_ftw_next(ftw, &cursor)) != NULL) {
		const char *upper_path;

		if (d->d_type != DT_DIR)
			continue;

		upper_path = __pathutil_concat2(upperdir, cursor.relative_path);
		(void) fsutil_makedirs(upper_path, cursor.st->st_mode | 0700);
		if (dir_list)
			strutil_array_append(dir_list, upper_path);
	}

	fsutil_ftw_ctx_free(ftw);
	return true;
}

/*
 * Return the layer path for a given layer name and type.
 */
char *
wormhole_layer_make_path(const char *target_name, int target_type)
{
	const char *base_path;
	char *result = NULL;

	if (target_type < 0 || __LAYER_TYPE_MAX <= target_type)
		return NULL;

	/* In case the caller missed it */
	wormhole_layer_set_default_search_path();

	base_path = layer_defaults.path[target_type];
	if (base_path == NULL)
		return NULL;

	pathutil_concat2(&result, base_path, target_name);
	return result;
}

/*
 * For semi-transparent mounts we need a "layer" that represents the
 * system.
 */
struct wormhole_layer *
wormhole_layer_get_system(void)
{
	static struct wormhole_layer *_system = NULL;

	if (_system == NULL) {
		_system = calloc(1, sizeof(*_system));
		_system->refcount = 1;
		_system->name = strdup("<system>");
		_system->depth = 0;

		_system->image_path = "/";
	}

	return _system;
}
