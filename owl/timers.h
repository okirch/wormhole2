
#ifndef TIMERS_H
#define TIMERS_H

typedef struct owl_timer owl_timer_t;

/*
 * Create a global timer.
 */
extern owl_timer_t *	owl_timer_create(unsigned long timeout_ms);

/*
 * Timer functions
 */
extern void		owl_timer_set_callback(owl_timer_t *, void (*callback)(owl_timer_t *, void *), void *);
extern void		owl_timer_hold(owl_timer_t *);
extern void		owl_timer_release(owl_timer_t *);
extern void		owl_timer_cancel(owl_timer_t *);
extern void		owl_timer_pause(owl_timer_t *);
extern void		owl_timer_unpause(owl_timer_t *);
extern long		owl_timer_remaining(const owl_timer_t *);
extern bool		owl_timer_is_expired(const owl_timer_t *);

/*
 * Timer objects
 */
enum {
	OWL_TIMER_STATE_ACTIVE,
	OWL_TIMER_STATE_PAUSED,
	OWL_TIMER_STATE_EXPIRED,
	OWL_TIMER_STATE_CANCELLED,
	OWL_TIMER_STATE_DEAD,
};

struct owl_timer {
	struct owl_timer **prev;
	struct owl_timer *	next;

	unsigned int		refcount;

	unsigned int		id;
	unsigned int		connection_id;

	int			state;
	struct timeval		runtime;
	struct timeval		expires;

	/* This callback is invoked when the timer expired.
	 */
	void			(*callback)(owl_timer_t *, void *user_data);
	void *			user_data;
};

typedef struct owl_timeout {
	struct timeval		now;
	struct timeval		until;
} owl_timeout_t;

typedef struct owl_timer_list {
	struct owl_timer *		head;
} owl_timer_list_t;

extern void		owl_timeout_init(owl_timeout_t *);
extern bool		owl_timeout_update(owl_timeout_t *, const struct timeval *deadline);
extern long		owl_timeout_msec(const owl_timeout_t *);

extern void		owl_timer_list_insert(owl_timer_list_t *list, struct owl_timer *timer);
extern void		owl_timer_list_update_timeout(owl_timer_list_t *, owl_timeout_t *);
extern void		owl_timer_list_expire(owl_timer_list_t *list);
extern void		owl_timer_list_reap(owl_timer_list_t *list, owl_timer_list_t *expired);
extern void		owl_timer_list_invoke(owl_timer_list_t *list);
extern void		owl_timer_list_destroy(owl_timer_list_t *list);

extern void		owl_timers_update_timeout(owl_timeout_t *tmo);
extern void		owl_timers_run(void);

#endif /* TIMERS_H */
