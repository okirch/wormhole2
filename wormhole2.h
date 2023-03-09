
#ifndef WORMHOLE2_H
#define WORMHOLE2_H

#include <stdbool.h>
#include "util.h"

typedef struct mount_farm mount_farm_t;
typedef struct mount_leaf mount_leaf_t;
typedef struct mount_bind mount_bind_t;

struct mount_farm {
	char *		upper_base;
	char *		work_base;
	char *		chroot;

	unsigned int	num_mounts;

	struct mount_leaf *root;
	struct mount_bind *binds;
};

struct mount_state {
	struct mount_leaf *root;
};

#define MOUNT_LEAF_LOWER_MAX	8

struct mount_leaf {
	struct mount_leaf *parent;
	struct mount_leaf *next;
	struct mount_leaf *children;

	bool		readonly;
	bool		nonempty;

	unsigned int	depth;
	char *		name;
	char *		relative_path;
	char *		full_path;
	char *		upper;
	char *		work;
	char *		mountpoint;

	char *		fstype;

	unsigned int	nlower;
	char *		lower[MOUNT_LEAF_LOWER_MAX];
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

	/* if 0, referenced by command line */
	unsigned int		depth;

	struct strutil_array	used;

	struct mount_state *	tree;
};

struct wormhole_layer_array {
	unsigned int		count;
	struct wormhole_layer **data;
};

struct wormhole_context {
	unsigned int		purpose;
	int			exit_status;

	char *			workspace;
	struct procutil_command	command;
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


extern struct wormhole_layer *	wormhole_layer_new(const char *name, const char *path, unsigned int depth);
extern void			wormhole_layer_free(struct wormhole_layer *layer);
extern bool			wormhole_layer_load_config(struct wormhole_layer *layer);
extern bool			wormhole_layer_save_config(struct wormhole_layer *layer);
extern void			wormhole_layer_array_append(struct wormhole_layer_array *a, struct wormhole_layer *layer);
extern struct wormhole_layer *	wormhole_layer_array_find(struct wormhole_layer_array *a, const char *name);
extern void			wormhole_layer_array_destroy(struct wormhole_layer_array *a);

#endif /* WORMHOLE2_H */
