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

#include "wormhole2.h"
#include "paths.h"
#include "tracing.h"
#include "util.h"

struct wormhole_layer *
wormhole_layer_new(const char *name, const char *path, unsigned int depth)
{
	struct wormhole_layer *layer;

	layer = calloc(1, sizeof(*layer));
	layer->name = strdup(name);
	layer->depth = depth;
	if (path)
		strutil_set(&layer->path, path);
	else
		pathutil_concat2(&layer->path, WORMHOLE_LAYER_BASE_PATH, name);
	pathutil_concat2(&layer->config_path, layer->path, "layer.conf");
	pathutil_concat2(&layer->image_path, layer->path, "image");
	pathutil_concat2(&layer->rpmdb_path, layer->path, "rpm.patch");

	return layer;
}

void
wormhole_layer_free(struct wormhole_layer *layer)
{
	strutil_set(&layer->name, NULL);
	strutil_set(&layer->path, NULL);
	strutil_set(&layer->image_path, NULL);
	strutil_set(&layer->rpmdb_path, NULL);

	if (layer->tree)
		mount_state_free(layer->tree);
	layer->tree = NULL;

	free(layer);
}

void
wormhole_layer_array_append(struct wormhole_layer_array *a, struct wormhole_layer *layer)
{
	if ((a->count & 15) == 0) {
		a->data = realloc(a->data, (a->count + 16) * sizeof(a->data[0]));
	}

	a->data[a->count++] = layer;
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
		wormhole_layer_free(a->data[i]);

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
		if (!strcmp(kwd, "directory")) {
			strutil_array_append(&layer->directories, value);
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
	for (i = 0; i < layer->directories.count; ++i)
		fprintf(fp, "directory=%s\n", layer->directories.data[i]);

	fclose(fp);
	return true;
}

static bool
__wormhole_layers_resolve(struct wormhole_layer_array *layers, const char *name, unsigned int depth)
{
	struct wormhole_layer *layer = NULL;
	unsigned int i;

	if (depth > 100) {
		log_error("too many nested layers, possibly a circular reference");
		return false;
	}

	if (wormhole_layer_array_find(layers, name))
		return true;

	layer = wormhole_layer_new(name, NULL, depth);

	if (!wormhole_layer_load_config(layer))
		goto failed;

	/* Now resolve the lower layers referenced by this one */
	for (i = 0; i < layer->used.count; ++i) {
		if (!__wormhole_layers_resolve(layers, layer->used.data[i], depth + 1))
			goto failed;
	}

	wormhole_layer_array_append(layers, layer);
	return true;

failed:
	if (layer)
		wormhole_layer_free(layer);
	return false;
}

bool
wormhole_layers_resolve(struct wormhole_layer_array *a, const char *name)
{
	return __wormhole_layers_resolve(a, name, 0);
}
