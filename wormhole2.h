
#ifndef WORMHOLE2_H
#define WORMHOLE2_H

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

#define CONTEXT_LOWER_MAX	8

struct wormhole_layer {
	char *			name;
	char *			path;
	char *			image_path;
	char *			rpmdb_path;

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

extern bool		mount_state_discover(const char *mtab,
				bool (*report_fn)(void *user_data,
						const char *mount_point,
						const char *mnt_type,
						const char *fsname),
				void *user_data);

#endif /* WORMHOLE2_H */
