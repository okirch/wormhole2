
#ifndef WORMHOLE2_H
#define WORMHOLE2_H

#include <stdbool.h>
#include "util.h"

typedef struct mount_farm mount_farm_t;
typedef struct fstree_node fstree_node_t;
typedef const struct mount_ops	mount_ops_t;

struct wormhole_layer_array {
	unsigned int		count;
	struct wormhole_layer **data;
};

struct mount_farm {
	char *		upper_base;
	char *		work_base;
	char *		chroot;

	struct {
		mount_ops_t *overlay;
		mount_ops_t *bind;
	} mount_ops;

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
	WORMHOLE_EXPORT_AS_IS,
	WORMHOLE_EXPORT_ROOT,
	WORMHOLE_EXPORT_STACKED,
	WORMHOLE_EXPORT_TRANSPARENT,
	WORMHOLE_EXPORT_SEMITRANSPARENT,
	WORMHOLE_EXPORT_MOUNTIT,
	WORMHOLE_EXPORT_HIDE,
};

struct mount_ops {
	const char *		name;
	bool			(*mount)(const struct fstree_node *);
};

#define FSTREE_NODE_F_READONLY	0x0001
#define FSTREE_NODE_F_MAYREPLACE 0x0002
#define FSTREE_NODE_F_TRACK	0x0004
#define FSTREE_NODE_F_MODIFIED	0x0008

struct fstree_node {
	struct fstree_node *parent;
	struct fstree_node *next;
	struct fstree_node *children;

	const struct fsroot *root;

	int		export_flags;
	int		export_type;
	int		dtype;

	unsigned int	depth;
	char *		name;
	char *		relative_path;
	char *		full_path;
	char *		upper;
	char *		work;

	mount_ops_t *	mount_ops;

	fsutil_mount_req_t mount;

	struct wormhole_layer *bind_mount_override_layer;
	struct wormhole_layer_array attached_layers;
};

typedef enum {
	MOUNT_ORIGIN_LAYER,
	MOUNT_ORIGIN_SYSTEM,
} mount_origin_t;

typedef enum {
	MOUNT_MODE_OVERLAY,
	MOUNT_MODE_BIND,
} mount_mode_t;

struct mount_config {
	unsigned int		refcount;
	char *			path;
	int			dtype;	/* for now, DT_DIR or DT_REG */
	mount_mode_t		mode;
	mount_origin_t		origin;
};

struct mount_config_array {
	unsigned int		count;
	struct mount_config **	data;
};

struct wormhole_layer {
	unsigned int		refcount;

	char *			name;
	char *			path;
	char *			config_path;
	char *			image_path;
	char *			wrapper_path;
	char *			rpmdb_path;

	bool			is_root;

	struct mount_config_array mounts;
	struct strutil_array	entry_points;
	struct strutil_mapping	entry_point_symlinks;

	/* if 0, referenced by command line */
	unsigned int		depth;

	struct strutil_array	used;
};

enum {
	PURPOSE_NONE,
	PURPOSE_BUILD,
	PURPOSE_USE,
	PURPOSE_BOOT,
};

enum {
	WORMHOLE_BASE_LAYER_HOST = 1,
	WORMHOLE_BASE_LAYER_CONTAINER,
};

enum {
	LAYER_TYPE_USER = 0,
	LAYER_TYPE_SITE,
	LAYER_TYPE_SYSTEM,

	__LAYER_TYPE_MAX
};

struct wormhole_layer_config {
	/* This is where we remount the $layer/image directories to shorten the path names */
	char *			remount_image_base;
	bool			use_system_root;
	struct strutil_array	names;
	struct wormhole_layer_array array;
};

struct wormhole_context {
	unsigned int		purpose;
	int			exit_status;

	/* This was the current working directory when we started. */
	char *			working_directory;

	char *			workspace;


	struct procutil_command	command;

	struct wormhole_layer_config layer;

	/* PURPOSE_BUILD */
	struct {
		int		target_type;
		char *		target;
		char *		root;
		char *		bindir;
		bool		fudge_layer_dir_permissions;

		struct strutil_array purge_directories;
	} build;

	/* PURPOSE_BOOT */
	struct {
		fsutil_mount_detail_t *mount_detail;
		char *		prep_script;
	} boot;

	struct mount_farm *	farm;

	/* FIXME: replace this with flags? */
	bool			manage_rpmdb;
	bool			map_caller_to_root;
	bool			use_privileged_namespace;
	bool			running_inside_chroot;
	bool			no_switch_root;
	bool			auto_entry_points;
	bool			force;
	bool			no_selinux;
	bool			remount_layers;

	struct fsutil_tempdir	temp;
};

/* Flags for fstree_add_export */
#define FSTREE_ADD_REPLACE_LAYERS	0x0001
#define FSTREE_QUIET			0x0002

extern mount_ops_t		mount_ops_overlay;
extern mount_ops_t		mount_ops_overlay_host;
extern mount_ops_t		mount_ops_bind;
extern mount_ops_t		mount_ops_tmpfs;
extern mount_ops_t		mount_ops_mountcmd;
extern mount_ops_t		mount_ops_direct;

struct fstree *			fstree_new(const char *root_path);
extern void			fstree_free(struct fstree *fstree);
extern struct fstree_node *	fstree_create_leaf(struct fstree *fstree, const char *relative_path);
extern const char *		fstree_get_full_path(struct fstree *fstree, const char *relative_path);
extern struct fstree_node *	fstree_add_export(struct fstree *fstree, const char *system_path,
					unsigned int export_type, int dtype,
					struct wormhole_layer *layer,
					int flags);
extern bool			fstree_hide_pattern(struct fstree *fstree, const char *pattern);
extern void			fstree_print(struct fstree *tree);

extern struct fstree_iter *	fstree_iterator_new(struct fstree *fstree, bool depth_first);
extern struct fstree_node *	fstree_iterator_next(struct fstree_iter *);
extern void			fstree_iterator_skip(struct fstree_iter *, struct fstree_node *);
extern void			fstree_iterator_free(struct fstree_iter *);

extern void			mount_config_array_init(struct mount_config_array *);
extern void			mount_config_array_destroy(struct mount_config_array *);
extern struct mount_config *	mount_config_array_add(struct mount_config_array *, const char *path, int dtype,
					mount_origin_t origin, mount_mode_t mode);
extern struct mount_config *	mount_config_array_append(struct mount_config_array *, struct mount_config *);
extern struct mount_config *	mount_config_array_get(struct mount_config_array *, const char *path);

extern struct mount_farm *	mount_farm_new(int purpose, const char *farm_root);
extern void			mount_farm_free(struct mount_farm *farm);
extern bool			mount_farm_create_workspace(struct mount_farm *farm);
extern bool			mount_farm_set_upper_base(struct mount_farm *farm, const char *upper_base);
extern bool			mount_farm_use_system_root(struct mount_farm *farm);
extern struct fstree_node *	mount_farm_find_leaf(struct mount_farm *farm, const char *relative_path);
extern bool			mount_farm_mount_all(struct mount_farm *farm);
extern struct fstree_node *	mount_farm_add_system_dir(struct mount_farm *farm, const char *system_path);
extern bool			mount_farm_bind_system_dir(struct mount_farm *farm, const char *system_path);
extern struct fstree_node *	mount_farm_add_mount(struct mount_farm *farm, const struct mount_config *mnt, struct wormhole_layer *layer);
extern struct fstree_node *	mount_farm_add_stacked(struct mount_farm *farm, const char *system_path, struct wormhole_layer *layer);
extern struct fstree_node *	mount_farm_add_transparent(struct mount_farm *farm, const char *system_path,
					int dtype, struct wormhole_layer *layer);
extern bool			mount_farm_add_missing_children(struct mount_farm *farm, const char *system_path);
extern bool			mount_farm_percolate(struct mount_farm *farm);
extern bool			mount_farm_has_mount_for(struct mount_farm *farm, const char *path);
extern struct fstree_node *	mount_farm_add_virtual_mount(struct mount_farm *farm, const char *system_path, const char *fstype);
extern bool			mount_farm_mount_into(struct mount_farm *farm, const char *src, const char *dst);
extern void			mount_farm_print_tree(struct mount_farm *farm);

/* discovery code */
extern struct fstree *		system_mount_tree_discover(int base_layer, int purpose);

extern void			fstree_node_free(struct fstree_node *leaf);
extern struct fstree_node *	fstree_node_new(const char *name, const char *relative_path, const struct fsroot *root);
extern bool			fstree_node_is_mountpoint(const struct fstree_node *leaf);
extern bool			fstree_node_is_below_mountpoint(const struct fstree_node *leaf);
extern struct fstree_node *	fstree_node_lookup(struct fstree_node *parent, const char *relative_path, bool create);
extern struct fstree_node *	fstree_node_closest_ancestor(struct fstree_node *parent, const char *relative_path);
extern char *			fstree_node_relative_path(struct fstree_node *ancestor, struct fstree_node *node);
extern bool			fstree_node_set_fstype(struct fstree_node *leaf, mount_ops_t *ops, struct mount_farm *farm);
extern void			fstree_node_reset(struct fstree_node *leaf);
extern bool			fstree_node_add_lower(struct fstree_node *leaf, const char *path);
extern char *			fstree_node_build_lowerspec(const struct fstree_node *leaf, bool include_host_dir);
extern void			fstree_node_invalidate(struct fstree_node *leaf);
extern bool			fstree_node_zap_dirs(struct fstree_node *leaf);
extern bool			fstree_node_mount(const struct fstree_node *leaf);
extern bool			fstree_node_traverse(struct fstree_node *node, bool (*visitorfn)(const struct fstree_node *));
extern const char *		mount_export_type_as_string(int export_type);

static inline const char *
fstree_node_fstype(const struct fstree_node *node)
{
	return node->mount_ops? node->mount_ops->name : NULL;
}

extern void			wormhole_layer_config_destroy(struct wormhole_layer_config *);
extern bool			wormhole_layer_config_use_system_root(const struct wormhole_layer_config *);
extern int			wormhole_layer_config_base_layer_type(const struct wormhole_layer_config *);
extern void			wormhole_layer_set_default_search_path(void);
extern void			wormhole_layer_print_default_search_path(void);
extern struct wormhole_layer *	wormhole_layer_new(const char *name, const char *path, unsigned int depth);
extern struct wormhole_layer *	wormhole_layer_hold(struct wormhole_layer *layer);
extern void			wormhole_layer_release(struct wormhole_layer *layer);
extern bool			wormhole_layer_load_config(struct wormhole_layer *layer);
extern bool			wormhole_layer_save_config(struct wormhole_layer *layer);
extern bool			wormhole_layer_remount_image(struct wormhole_layer *layer, const char *image_base);
extern bool			wormhole_layer_create_default_wrapper_symlinks(struct wormhole_layer *layer);
extern bool			wormhole_layer_write_wrappers(struct wormhole_layer *layer, const char *install_bindir);
extern void			wormhole_layer_array_append(struct wormhole_layer_array *a, struct wormhole_layer *layer);
extern void			wormhole_layer_array_append_unique(struct wormhole_layer_array *a, struct wormhole_layer *layer);
extern void			wormhole_layer_array_prepend_unique(struct wormhole_layer_array *a, struct wormhole_layer *layer);
extern struct wormhole_layer *	wormhole_layer_array_find(struct wormhole_layer_array *a, const char *name);
extern void			wormhole_layer_array_destroy(struct wormhole_layer_array *a);
extern char *			wormhole_layer_make_path(const char *name, int target_type);
extern void			wormhole_layer_add_entry_point_symlink(struct wormhole_layer *layer, const char *entry_point_name, const char *symlink_path);
extern struct wormhole_layer *	wormhole_layer_get_system(void);

extern bool			wormhole_layer_update_from_mount_farm(struct wormhole_layer *layer, const struct fstree_node *tree);
extern bool			wormhole_layer_build_mount_farm(struct wormhole_layer *layer, struct mount_farm *farm);
extern bool			wormhole_layers_resolve(struct wormhole_layer_config *layers);
extern bool			wormhole_layers_remount(struct wormhole_layer_config *layers);
extern bool			wormhole_layer_copyup_directories(const struct wormhole_layer *layer, const char *upperdir,
					struct strutil_array *dir_list);

extern struct wormhole_layer *	__wormhole_layer_new(const char *name);

#endif /* WORMHOLE2_H */
