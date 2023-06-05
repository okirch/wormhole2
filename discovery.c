/*
 * wormhole - mount discovery code
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

#include <fnmatch.h>

#include "wormhole2.h"
#include "tracing.h"
#include "util.h"

#define BIND_SYSTEM_OVERLAYS	true

enum {
	WORMHOLE_RULE_SKIP,
	WORMHOLE_RULE_ATTACH,
	WORMHOLE_RULE_CONTINUE,
};

struct wormhole_attachment_rule {
	const char *		path;
	const char *		fstype;
	const char *		desc;

	bool			(*check)(const fsutil_mount_cursor_t *cursor, const struct wormhole_attachment_rule *rule);
	bool			(*attach)(const fsutil_mount_cursor_t *cursor, const struct wormhole_attachment_rule *rule, struct fstree *fstree);
};

#define WORMHOLE_ATTACHMENT_DESC(kind, value, verb)	.desc = #verb " " #kind " " value
#define WORMHOLE_ATTACHMENT_CHECK_PATH(__path, action) \
{ .path = __path, .check = wormhole_attachment_rule_check_path_equal, wormhole_attachment_rule_##action, \
	WORMHOLE_ATTACHMENT_DESC(path, __path, action) \
}
#define WORMHOLE_ATTACHMENT_CHECK_PREFIX(__path, action) \
{ .path = __path, .check = wormhole_attachment_rule_check_path_prefix, wormhole_attachment_rule_##action, \
	WORMHOLE_ATTACHMENT_DESC(prefix, __path, action) \
}
#define WORMHOLE_ATTACHMENT_CHECK_GLOB(__path, action) \
{ .path = __path, .check = wormhole_attachment_rule_check_path_glob, wormhole_attachment_rule_##action, \
	WORMHOLE_ATTACHMENT_DESC(prefix, __path, action) \
}
#define WORMHOLE_ATTACHMENT_CHECK_FSTYPE(__fstype, action) \
{ .fstype = __fstype, .check = wormhole_attachment_rule_check_fstype_equal, wormhole_attachment_rule_##action, \
	WORMHOLE_ATTACHMENT_DESC(fstype, __fstype, action) \
}
#define WORMHOLE_ATTACHMENT_DEFAULT(action) \
{ .check = wormhole_attachment_rule_check_true, wormhole_attachment_rule_##action, \
	.desc = #action " (default)" \
}

static const char *
wormhole_attachment_rule_print(const struct wormhole_attachment_rule *rule, const struct wormhole_attachment_rule *rule_base)
{
	static char buffer[128];
	unsigned int no = rule - rule_base;

	if (rule->desc)
		snprintf(buffer, sizeof(buffer), "rule %u: %s", no, rule->desc);
	else
		snprintf(buffer, sizeof(buffer), "rule %u", no);
	return buffer;
}

static bool
wormhole_attachment_rule_check_true(const fsutil_mount_cursor_t *cursor, const struct wormhole_attachment_rule *rule)
{
	return true;
}

static bool
wormhole_attachment_rule_check_path_equal(const fsutil_mount_cursor_t *cursor, const struct wormhole_attachment_rule *rule)
{
	return strutil_equal(cursor->mountpoint, rule->path);
}

static bool
wormhole_attachment_rule_check_path_prefix(const fsutil_mount_cursor_t *cursor, const struct wormhole_attachment_rule *rule)
{
	return fsutil_check_path_prefix(cursor->mountpoint, rule->path);
}

static bool
wormhole_attachment_rule_check_path_glob(const fsutil_mount_cursor_t *cursor, const struct wormhole_attachment_rule *rule)
{
	return fnmatch(rule->path, cursor->mountpoint, FNM_PATHNAME) == 0;
}

static bool
wormhole_attachment_rule_check_fstype_equal(const fsutil_mount_cursor_t *cursor, const struct wormhole_attachment_rule *rule)
{
	if (cursor->detail->fstype == NULL) {
		trace("system mount %s has null fstype", cursor->mountpoint);
		return false;
	}

	return strutil_equal(cursor->detail->fstype, rule->fstype);
}

static bool
wormhole_attachment_rule_skip(const fsutil_mount_cursor_t *cursor, const struct wormhole_attachment_rule *rule, struct fstree *fstree)
{
	return true;
}

static bool
wormhole_attachment_rule_hide(const fsutil_mount_cursor_t *cursor, const struct wormhole_attachment_rule *rule, struct fstree *fstree)
{
	struct fstree_node *node;

	trace("Hide %s", cursor->mountpoint);
	node = fstree_add_export(fstree, cursor->mountpoint, WORMHOLE_EXPORT_HIDE, DT_DIR, NULL, 0);
	if (node == NULL)
		return false;

	return true;
}

static bool
wormhole_attachment_rule_bind(const fsutil_mount_cursor_t *cursor, const struct wormhole_attachment_rule *rule, struct fstree *fstree)
{
	fsutil_mount_detail_t *md = cursor->detail;
	struct fstree_node *node;
	int dtype;

	dtype = fsutil_get_dtype(cursor->mountpoint);
	node = fstree_add_export(fstree, cursor->mountpoint, WORMHOLE_EXPORT_TRANSPARENT, dtype, NULL, 0);

	if (node == NULL) {
		log_error("failed to add node for system mount %s\n", cursor->mountpoint);
		return false;
	}

	if (node->mount.detail) {
		/* It's a setup problem for the system, but not a problem for us as we just bind mount
		 * what's there. */
		log_warning("%s: duplicate system mount (%s and %s)", cursor->mountpoint, node->mount.detail->fstype, md->fstype);
		return false;
	}

	node->mount.detail = fsutil_mount_detail_hold(md);
	node->mount_ops = &mount_ops_bind;
	return true;
}

static inline bool
wormhole_attachment_rule_export_overlay(const fsutil_mount_cursor_t *cursor, const struct wormhole_attachment_rule *rule, struct fstree *fstree)
{
	struct fstree_node *node;
	int dtype;
	struct wormhole_layer *l;
	unsigned int j;


	if (cursor->overlay.dirs->count == 0) {
		log_error("system mount %s is an overlay, but we didn't detect any layers",
				cursor->mountpoint);
		return false;
	}

	dtype = fsutil_get_dtype(cursor->mountpoint);
	node = fstree_add_export(fstree, cursor->mountpoint, WORMHOLE_EXPORT_STACKED, dtype, NULL, 0);

	if (node == NULL) {
		log_error("failed to add node for system mount %s\n", cursor->mountpoint);
		return false;
	}

	l = __wormhole_layer_new("system-layer");
	for (j = 0; j < cursor->overlay.dirs->count; ++j) {
		const char *overlay_path = cursor->overlay.dirs->data[j];

		mount_config_array_add(&l->mounts, overlay_path, DT_DIR,
				MOUNT_ORIGIN_LAYER, MOUNT_MODE_OVERLAY);
		strutil_set(&l->image_path, cursor->mountpoint);
	}

	wormhole_layer_array_append(&node->attached_layers, l);
	node->mount_ops = &mount_ops_overlay;
	return true;
}

static bool
wormhole_attachment_rule_track_changes(const fsutil_mount_cursor_t *cursor, const struct wormhole_attachment_rule *rule, struct fstree *fstree)
{
	static struct wormhole_layer *system_layer = NULL;
	struct fstree_node *node;
	int dtype;

	dtype = fsutil_get_dtype(cursor->mountpoint);

	/* We're unable to handle regular file mounts for now */
	if (dtype != DT_DIR) {
		log_error("%s: unable to handle non-directory %s", __func__, cursor->mountpoint);
		return false;
	}

	node = fstree_add_export(fstree, cursor->mountpoint, WORMHOLE_EXPORT_STACKED, dtype, NULL, 0);
	if (node == NULL) {
		log_error("failed to add node for system mount %s\n", cursor->mountpoint);
		return false;
	}

	if (system_layer == NULL) {
		system_layer = __wormhole_layer_new("system-layer");
		strutil_set(&system_layer->image_path, "/");
	}
#if 0
	mount_config_array_add(&system_layer->mounts, cursor->mountpoint, dtype,
			MOUNT_ORIGIN_SYSTEM, MOUNT_MODE_OVERLAY);
#endif

	wormhole_layer_array_append(&node->attached_layers, system_layer);
	node->mount_ops = &mount_ops_overlay;

	/* Setting this flag will cause the upperdir to be scanned for changes */
	node->export_flags |= FSTREE_NODE_F_TRACK;
	return true;
}

static struct wormhole_attachment_rule container_use_rules[] = {
	WORMHOLE_ATTACHMENT_CHECK_PATH("/", skip),
	WORMHOLE_ATTACHMENT_CHECK_FSTYPE("autofs", skip),

#if BIND_SYSTEM_OVERLAYS
	WORMHOLE_ATTACHMENT_CHECK_FSTYPE("overlay", bind),
#else
	WORMHOLE_ATTACHMENT_CHECK_FSTYPE("overlay", export_overlay),
#endif

	WORMHOLE_ATTACHMENT_CHECK_PREFIX("/bin", hide),
	WORMHOLE_ATTACHMENT_CHECK_PREFIX("/sbin", hide),
	WORMHOLE_ATTACHMENT_CHECK_PREFIX("/lib", hide),
	WORMHOLE_ATTACHMENT_CHECK_PREFIX("/lib64", hide),
	WORMHOLE_ATTACHMENT_CHECK_PREFIX("/usr", hide),
	WORMHOLE_ATTACHMENT_CHECK_PREFIX("/boot", hide),
	WORMHOLE_ATTACHMENT_CHECK_PREFIX("/.snapshots", hide),
	WORMHOLE_ATTACHMENT_CHECK_PREFIX("/var/lib/overlay", hide),
	WORMHOLE_ATTACHMENT_CHECK_PREFIX("/var/lib/containers", hide),
	WORMHOLE_ATTACHMENT_CHECK_PREFIX("/var/lib/wormhole", hide),

	/* Note the difference between a prefix check and this glob check.
	 * Checking for prefix /tmp would match a mount on /tmp and all
	 * mounts below.
	 * Checking for a glob of /tmp/ * will only match mounts below
	 * /tmp, but not /tmp itself. */
	WORMHOLE_ATTACHMENT_CHECK_GLOB("/tmp/*", hide),

	WORMHOLE_ATTACHMENT_DEFAULT(bind),

	{ NULL }
};

/* Just to get it build - this is not functional right now */
#define container_build_rules container_use_rules

static struct wormhole_attachment_rule host_build_rules[] = {
	WORMHOLE_ATTACHMENT_CHECK_FSTYPE("autofs", skip),

	WORMHOLE_ATTACHMENT_CHECK_PATH("/", track_changes),
	WORMHOLE_ATTACHMENT_CHECK_PREFIX("/usr", track_changes),
	WORMHOLE_ATTACHMENT_CHECK_PREFIX("/lib", track_changes),
	WORMHOLE_ATTACHMENT_CHECK_PREFIX("/lib64", track_changes),
	WORMHOLE_ATTACHMENT_CHECK_PREFIX("/bin", track_changes),
	WORMHOLE_ATTACHMENT_CHECK_PREFIX("/sbin", track_changes),
	WORMHOLE_ATTACHMENT_CHECK_PREFIX("/etc", track_changes),
	WORMHOLE_ATTACHMENT_CHECK_PREFIX("/opt", track_changes),

	WORMHOLE_ATTACHMENT_CHECK_PREFIX("/boot", skip),
	WORMHOLE_ATTACHMENT_CHECK_PREFIX("/.snapshots", skip),
	WORMHOLE_ATTACHMENT_CHECK_PREFIX("/var/lib/overlay", skip),
	WORMHOLE_ATTACHMENT_CHECK_PREFIX("/var/lib/containers", skip),
	WORMHOLE_ATTACHMENT_CHECK_PREFIX("/var/lib/wormhole", skip),
	WORMHOLE_ATTACHMENT_CHECK_GLOB("/tmp/*", skip),

	WORMHOLE_ATTACHMENT_DEFAULT(bind),

	{ NULL }
};

static struct wormhole_attachment_rule host_use_rules[] = {
	{ NULL }
};

static bool
system_mount_tree_maybe_attach(struct fstree *fstree, const fsutil_mount_cursor_t *cursor, const struct wormhole_attachment_rule *rules)
{
	const struct wormhole_attachment_rule *r;
	fsutil_mount_detail_t *md = cursor->detail;

	if (md->fstype == NULL) {
		trace("system mount %s has null fstype", cursor->mountpoint);
		return false;
	}

	for (r = rules; r->check; ++r) {
		if (!r->check(cursor, r))
			continue;

		if (!r->attach(cursor, r, fstree)) {
			log_error("unable to attach %s (matched by rule #%u)",
					cursor->mountpoint,
					wormhole_attachment_rule_print(r, rules));
			return false;
		}

		trace2("  %s matched by %s", 
				cursor->mountpoint,
				wormhole_attachment_rule_print(r, rules));
		return true;
	}

	return true;
}

static struct fstree *
system_mount_tree_discover_rules(const struct wormhole_attachment_rule *rules)
{
	fsutil_mount_iterator_t *it;
	fsutil_mount_cursor_t cursor;
	struct fstree *fstree;

	if (!(it = fsutil_mount_iterator_create(NULL, FSUTIL_MTAB_ITERATOR, NULL)))
		return NULL;

	fstree = fstree_new(NULL);

	while (fsutil_mount_iterator_next(it, &cursor)) {
		system_mount_tree_maybe_attach(fstree, &cursor, rules);
	}

	fsutil_mount_iterator_free(it);

	if (fstree->root->export_type == WORMHOLE_EXPORT_NONE)
		fstree->root->export_type = WORMHOLE_EXPORT_ROOT;

	return fstree;
}

#define SMTD_COMBINE(l, p)	(((l) << 8) | p)

struct fstree *
system_mount_tree_discover(int base_layer, int purpose)
{
	int what = SMTD_COMBINE(base_layer, purpose);

	switch (what) {
	case SMTD_COMBINE(WORMHOLE_BASE_LAYER_HOST, PURPOSE_BUILD):
		return system_mount_tree_discover_rules(host_build_rules);
	case SMTD_COMBINE(WORMHOLE_BASE_LAYER_HOST, PURPOSE_USE):
		/* Maybe it'd be enough to just return an empty fstree here. */
		return system_mount_tree_discover_rules(host_use_rules);
	case SMTD_COMBINE(WORMHOLE_BASE_LAYER_CONTAINER, PURPOSE_USE):
		return system_mount_tree_discover_rules(container_use_rules);
	case SMTD_COMBINE(WORMHOLE_BASE_LAYER_CONTAINER, PURPOSE_BUILD):
		return system_mount_tree_discover_rules(container_build_rules);
	default:
		break;
	}

	log_error("%s: not implemented for base_layer=%d, purpose=%d", __func__, base_layer, purpose);
	return NULL;
}

/*
 * Old, slated to go away
 */
#if 0
struct fstree *
system_mount_tree_discover_transparent(void)
{
	fsutil_mount_iterator_t *it;
	fsutil_mount_cursor_t cursor;
	struct fstree *fstree;

	if (!(it = fsutil_mount_iterator_create(NULL, FSUTIL_MTAB_ITERATOR, NULL)))
		return NULL;

	fstree = fstree_new(NULL);

	while (fsutil_mount_iterator_next(it, &cursor))
		system_mount_tree_maybe_add_transparent(fstree, &cursor);

	fsutil_mount_iterator_free(it);

	fstree->root->export_type = WORMHOLE_EXPORT_ROOT;

	fstree_hide_pattern(fstree, "/tmp/*");
	fstree_hide_pattern(fstree, "/usr");
	fstree_hide_pattern(fstree, "/lib");
	fstree_hide_pattern(fstree, "/lib64");
	fstree_hide_pattern(fstree, "/bin");
	fstree_hide_pattern(fstree, "/sbin");
	fstree_hide_pattern(fstree, "/boot");
	fstree_hide_pattern(fstree, "/.snapshots");
	fstree_hide_pattern(fstree, "/var/lib/overlay");
	fstree_hide_pattern(fstree, "/var/lib/containers");
	fstree_hide_pattern(fstree, "/var/lib/wormhole");

	return fstree;
}
#endif
