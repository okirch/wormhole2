
#ifndef WORMHOLE2_H
#define WORMHOLE2_H

#include <stdbool.h>
#include "util.h"

typedef struct mount_farm mount_farm_t;
typedef struct mount_leaf mount_leaf_t;
typedef struct mount_bind mount_bind_t;

struct wormhole_layer_array {
	unsigned int		count;
	struct wormhole_layer **data;
};

struct mount_farm {
	char *		upper_base;
	char *		work_base;
	char *		chroot;

	unsigned int	num_mounts;

	struct mount_state *tree;
	struct mount_bind *binds;
};

struct mount_state {
	struct mount_leaf *root;
};

#define MOUNT_LEAF_LOWER_MAX	8

enum {
	WORMHOLE_EXPORT_ERROR = -1,
	WORMHOLE_EXPORT_NONE,
	WORMHOLE_EXPORT_ROOT,
	WORMHOLE_EXPORT_STACKED,
	WORMHOLE_EXPORT_TRANSPARENT,
};

struct mount_leaf {
	struct mount_leaf *parent;
	struct mount_leaf *next;
	struct mount_leaf *children;

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

	unsigned int	nlower;
	char *		lower[MOUNT_LEAF_LOWER_MAX];

	struct wormhole_layer *bind_mount_override_layer;
	struct wormhole_layer_array attached_layers;
};

struct mount_bind {
	struct mount_bind *next;

	char *		source;
	char *		dest;
};

#define LOWER_LAYERS_MAX	8

struct wormhole_layer {
	char *			name;
	char *			path;
	char *			config_path;
	char *			image_path;
	char *			rpmdb_path;

	bool			is_root;

	struct strutil_array	stacked_directories;
	struct strutil_array	transparent_directories;

	/* if 0, referenced by command line */
	unsigned int		depth;

	struct strutil_array	used;
};

struct wormhole_context {
	unsigned int		purpose;
	int			exit_status;

	char *			workspace;
	char *			layer_path;

	struct procutil_command	command;

	struct strutil_array	layer_names;
	struct wormhole_layer_array layers;

	char *			build_target;
	char *			build_root;

	struct mount_farm *	farm;

	bool			manage_rpmdb;
	bool			use_privileged_namespace;

	struct fsutil_tempdir	temp;
};

struct mount_state *		mount_state_new(void);
extern void			mount_state_free(struct mount_state *state);
extern struct mount_leaf *	mount_state_create_leaf(struct mount_state *state, const char *relative_path);
extern bool			mount_state_make_relative(struct mount_state *state,
					const char *common_root);
extern bool			mount_state_discover(const char *mtab,
					bool (*report_fn)(void *user_data,
							const char *mount_point,
							const char *mnt_type,
							const char *fsname),
					void *user_data);
extern struct mount_leaf *	mount_state_add_export(struct mount_state *state, const char *system_path,
					unsigned int export_type, struct wormhole_layer *layer);

extern struct mount_state_iter *mount_state_iterator_new(struct mount_state *state);
extern struct mount_leaf *	mount_state_iterator_next(struct mount_state_iter *);
extern void			mount_state_iterator_skip(struct mount_state_iter *, struct mount_leaf *);
extern void			mount_state_iterator_free(struct mount_state_iter *);

extern struct mount_farm *	mount_farm_new(const char *farm_root);
extern void			mount_farm_free(struct mount_farm *farm);
extern bool			mount_farm_create_workspace(struct mount_farm *farm);
extern bool			mount_farm_set_upper_base(struct mount_farm *farm, const char *upper_base);
extern struct mount_leaf *	mount_farm_find_leaf(struct mount_farm *farm, const char *relative_path);
extern bool			mount_farm_mount_all(struct mount_farm *farm);
extern struct mount_leaf *	mount_farm_add_system_dir(struct mount_farm *farm, const char *system_path);
extern bool			mount_farm_bind_system_dir(struct mount_farm *farm, const char *system_path);
extern struct mount_leaf *	mount_farm_add_stacked(struct mount_farm *farm, const char *system_path, struct wormhole_layer *layer);
extern struct mount_leaf *	mount_farm_add_transparent(struct mount_farm *farm, const char *system_path, struct wormhole_layer *layer);
extern bool			mount_farm_add_missing_children(struct mount_farm *farm, const char *system_path);
extern bool			mount_farm_percolate(struct mount_farm *farm);
extern bool			mount_farm_has_mount_for(struct mount_farm *farm, const char *path);
extern struct mount_leaf *	mount_farm_add_virtual_mount(struct mount_farm *farm, const char *system_path, const char *fstype);
extern bool			mount_farm_mount_into(struct mount_farm *farm, const char *src, const char *dst);
extern void			mount_farm_print_tree(struct mount_farm *farm);

extern void			mount_leaf_free(struct mount_leaf *leaf);
extern struct mount_leaf *	mount_leaf_new(const char *name, const char *relative_path);
extern bool		mount_leaf_is_mountpoint(const struct mount_leaf *leaf);
extern bool		mount_leaf_is_below_mountpoint(const struct mount_leaf *leaf);
extern struct mount_leaf *	mount_leaf_lookup(struct mount_leaf *parent, const char *relative_path, bool create);
extern bool			mount_leaf_set_fstype(struct mount_leaf *leaf, const char *fstype, struct mount_farm *farm);
extern bool			mount_leaf_add_lower(struct mount_leaf *leaf, const char *path);
extern char *			mount_leaf_build_lowerspec(const struct mount_leaf *leaf);
extern bool			mount_leaf_mount(const struct mount_leaf *leaf);
extern bool			mount_leaf_traverse(struct mount_leaf *node, bool (*visitorfn)(const struct mount_leaf *));
extern void			mount_tree_print(struct mount_leaf *leaf);
extern const char *		mount_export_type_as_string(int export_type);

extern struct wormhole_layer *	wormhole_layer_new(const char *name, const char *path, unsigned int depth);
extern void			wormhole_layer_free(struct wormhole_layer *layer);
extern bool			wormhole_layer_load_config(struct wormhole_layer *layer);
extern bool			wormhole_layer_save_config(struct wormhole_layer *layer);
extern void			wormhole_layer_array_append(struct wormhole_layer_array *a, struct wormhole_layer *layer);
extern struct wormhole_layer *	wormhole_layer_array_find(struct wormhole_layer_array *a, const char *name);
extern void			wormhole_layer_array_destroy(struct wormhole_layer_array *a);

extern bool			wormhole_layer_update_from_mount_farm(struct wormhole_layer *layer, const struct mount_leaf *tree);
extern bool			wormhole_layer_build_mount_farm(struct wormhole_layer *layer, struct mount_farm *farm);
extern bool			wormhole_layers_resolve(struct wormhole_layer_array *a, const char *name);

#endif /* WORMHOLE2_H */
