
#ifndef WORMHOLE2_H
#define WORMHOLE2_H

#include <stdbool.h>
#include "util.h"

typedef struct mount_farm mount_farm_t;
typedef struct fstree_node fstree_node_t;

struct wormhole_layer_array {
	unsigned int		count;
	struct wormhole_layer **data;
};

struct mount_farm {
	char *		upper_base;
	char *		work_base;
	char *		chroot;

	unsigned int	num_mounts;

	struct fstree *tree;
};

struct fsroot {
	char *		path;
};

struct fstree {
	struct fsroot *		root_location;
	struct fstree_node *	root;		/* FIXME: rename to root_node */
};

#define MOUNT_LEAF_LOWER_MAX	8

enum {
	WORMHOLE_EXPORT_ERROR = -1,
	WORMHOLE_EXPORT_NONE,
	WORMHOLE_EXPORT_ROOT,
	WORMHOLE_EXPORT_STACKED,
	WORMHOLE_EXPORT_TRANSPARENT,
};

struct fstree_node {
	struct fstree_node *parent;
	struct fstree_node *next;
	struct fstree_node *children;

	const struct fsroot *root;
	bool		readonly;
	bool		nonempty;

	int		export_type;
	int		dtype;

	unsigned int	depth;
	char *		name;
	char *		relative_path;
	char *		full_path;
	char *		upper;
	char *		work;
	char *		mountpoint;

	char *		fstype;
	char *		fsname;
	struct strutil_array	system_overlay_dirs;

	struct wormhole_layer *bind_mount_override_layer;
	struct wormhole_layer_array attached_layers;
};

#define LOWER_LAYERS_MAX	8

struct wormhole_layer {
	unsigned int		refcount;

	char *			name;
	char *			path;
	char *			config_path;
	char *			image_path;
	char *			wrapper_path;
	char *			rpmdb_path;

	bool			is_root;

	struct strutil_array	stacked_directories;
	struct strutil_array	transparent_directories;
	struct strutil_array	entry_points;

	/* if 0, referenced by command line */
	unsigned int		depth;

	struct strutil_array	used;
};

enum {
	PURPOSE_NONE,
	PURPOSE_BUILD,
	PURPOSE_USE,
	PURPOSE_BOOT,

	__PURPOSE_MESSING_AROUND,
};

enum {
	BUILD_USER_LAYER,
	BUILD_SYSTEM_LAYER,
};

struct wormhole_context {
	unsigned int		purpose;
	int			exit_status;

	/* This was the current working directory when we started. */
	char *			working_directory;

	char *			workspace;

	/* This is where we remount the $layer/image directories to shorten the path names */
	char *			image_path;

	struct procutil_command	command;

	struct strutil_array	layer_names;
	struct wormhole_layer_array layers;

	/* PURPOSE_BUILD */
	int			build_target_type;
	char *			build_target;
	char *			build_root;
	char *			build_bindir;

	/* PURPOSE_BOOT */
	char *			boot_device;
	char *			boot_fstype;

	struct mount_farm *	farm;

	bool			manage_rpmdb;
	bool			map_caller_to_root;
	bool			use_privileged_namespace;
	bool			running_inside_chroot;
	bool			auto_entry_points;
	bool			force;

	struct fsutil_tempdir	temp;
};

struct fstree *			fstree_new(const char *root_path);
extern void			fstree_free(struct fstree *fstree);
extern struct fstree_node *	fstree_create_leaf(struct fstree *fstree, const char *relative_path);
extern const char *		fstree_get_full_path(struct fstree *fstree, const char *relative_path);
extern struct fstree_node *	fstree_add_export(struct fstree *fstree, const char *system_path,
					unsigned int export_type, struct wormhole_layer *layer);
extern bool			fstree_drop_pattern(struct fstree *fstree, const char *pattern, struct strutil_array *dropped);
extern void			fstree_print(struct fstree *tree);

extern struct fstree_iter *	fstree_iterator_new(struct fstree *fstree, bool depth_first);
extern struct fstree_node *	fstree_iterator_next(struct fstree_iter *);
extern void			fstree_iterator_skip(struct fstree_iter *, struct fstree_node *);
extern void			fstree_iterator_free(struct fstree_iter *);

extern struct mount_farm *	mount_farm_new(const char *farm_root);
extern void			mount_farm_free(struct mount_farm *farm);
extern bool			mount_farm_create_workspace(struct mount_farm *farm);
extern bool			mount_farm_set_upper_base(struct mount_farm *farm, const char *upper_base);
extern struct fstree_node *	mount_farm_find_leaf(struct mount_farm *farm, const char *relative_path);
extern bool			mount_farm_mount_all(struct mount_farm *farm);
extern struct fstree_node *	mount_farm_add_system_dir(struct mount_farm *farm, const char *system_path);
extern bool			mount_farm_bind_system_dir(struct mount_farm *farm, const char *system_path);
extern struct fstree_node *	mount_farm_add_stacked(struct mount_farm *farm, const char *system_path, struct wormhole_layer *layer);
extern struct fstree_node *	mount_farm_add_transparent(struct mount_farm *farm, const char *system_path, struct wormhole_layer *layer);
extern bool			mount_farm_add_missing_children(struct mount_farm *farm, const char *system_path);
extern bool			mount_farm_percolate(struct mount_farm *farm);
extern bool			mount_farm_has_mount_for(struct mount_farm *farm, const char *path);
extern struct fstree_node *	mount_farm_add_virtual_mount(struct mount_farm *farm, const char *system_path, const char *fstype);
extern bool			mount_farm_mount_into(struct mount_farm *farm, const char *src, const char *dst);
extern void			mount_farm_print_tree(struct mount_farm *farm);

extern void			fstree_node_free(struct fstree_node *leaf);
extern struct fstree_node *	fstree_node_new(const char *name, const char *relative_path, const struct fsroot *root);
extern bool			fstree_node_is_mountpoint(const struct fstree_node *leaf);
extern bool			fstree_node_is_below_mountpoint(const struct fstree_node *leaf);
extern struct fstree_node *	fstree_node_lookup(struct fstree_node *parent, const char *relative_path, bool create);
extern char *			fstree_node_relative_path(struct fstree_node *ancestor, struct fstree_node *node);
extern bool			fstree_node_set_fstype(struct fstree_node *leaf, const char *fstype, struct mount_farm *farm);
extern bool			fstree_node_add_lower(struct fstree_node *leaf, const char *path);
extern char *			fstree_node_build_lowerspec(const struct fstree_node *leaf);
extern void			fstree_node_invalidate(struct fstree_node *leaf);
extern bool			fstree_node_zap_dirs(struct fstree_node *leaf);
extern bool			fstree_node_mount(const struct fstree_node *leaf);
extern bool			fstree_node_traverse(struct fstree_node *node, bool (*visitorfn)(const struct fstree_node *));
extern const char *		mount_export_type_as_string(int export_type);

extern struct wormhole_layer *	wormhole_layer_new(const char *name, const char *path, unsigned int depth);
extern struct wormhole_layer *	wormhole_layer_hold(struct wormhole_layer *layer);
extern void			wormhole_layer_release(struct wormhole_layer *layer);
extern bool			wormhole_layer_load_config(struct wormhole_layer *layer);
extern bool			wormhole_layer_save_config(struct wormhole_layer *layer);
extern bool			wormhole_layer_remount_image(struct wormhole_layer *layer, const char *image_base);
extern bool			wormhole_layer_write_wrappers(struct wormhole_layer *layer, const char *install_bindir);
extern void			wormhole_layer_array_append(struct wormhole_layer_array *a, struct wormhole_layer *layer);
extern void			wormhole_layer_array_append_unique(struct wormhole_layer_array *a, struct wormhole_layer *layer);
extern struct wormhole_layer *	wormhole_layer_array_find(struct wormhole_layer_array *a, const char *name);
extern void			wormhole_layer_array_destroy(struct wormhole_layer_array *a);
extern char *			wormhole_layer_make_path(const char *name, int target_type);

extern bool			wormhole_layer_update_from_mount_farm(struct wormhole_layer *layer, const struct fstree_node *tree);
extern bool			wormhole_layer_build_mount_farm(struct wormhole_layer *layer, struct mount_farm *farm);
extern bool			wormhole_layers_resolve(struct wormhole_layer_array *layers, const struct strutil_array *names, const char *remount_image_base);

#endif /* WORMHOLE2_H */
