/*
 * Timer handling routines
 * 
 * Copyright (C) 2014-2023 SUSE
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <sys/time.h>
#include <stdbool.h>
#include <signal.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>

#include "timers.h"
#include "tracing.h"
#include "util.h"


static unsigned int		__global_timer_id = 1;
static owl_timer_list_t		__global_timer_list;

/*
 * List helper functions
 */
static inline void
__owl_timer_insert(owl_timer_t **pos, owl_timer_t *timer)
{
	owl_timer_t *next = *pos;

	timer->next = *pos;
	timer->prev = pos;

	if (next)
		next->prev = &timer->next;

	*pos = timer;
}

static inline void
__owl_timer_unlink(owl_timer_t *timer)
{
	owl_timer_t **pos, *next;

	next = timer->next;
	if ((pos = timer->prev) != NULL) {
		*pos = next;
		if (next)
			next->prev = pos;

		timer->prev = NULL;
		timer->next = NULL;
	}
}

static inline void
__owl_timer_list_validate(owl_timer_list_t *list)
{
	owl_timer_t **pos, *t;

	for (pos = &list->head; (t = *pos) != NULL; pos = &t->next) {
		assert(t->prev == pos);
	}
}

owl_timer_t *
owl_timer_create(unsigned long timeout_ms)
{
	struct timeval now;
	owl_timer_t *timer;

	timer = calloc(1, sizeof(*timer));
	timer->refcount = 1;
	timer->id = __global_timer_id++;

	gettimeofday(&now, NULL);
	timer->runtime.tv_sec = timeout_ms / 1000;
	timer->runtime.tv_usec = (timeout_ms % 1000) * 1000;
	timeradd(&now, &timer->runtime, &timer->expires);

	timer->state = OWL_TIMER_STATE_ACTIVE;
	owl_timer_list_insert(&__global_timer_list, timer);

	log_debug("Created timer %u", timer->id);
	return timer;
}

void
owl_timer_set_callback(owl_timer_t *timer, void (*callback)(owl_timer_t *, void *), void *user_data)
{
	timer->callback = callback;
	timer->user_data = user_data;
}

static void
__owl_timer_free(owl_timer_t *timer)
{
	log_debug("Deleting timer %u", timer->id);
	assert(timer->prev == NULL);
	free(timer);
}

void
owl_timer_hold(owl_timer_t *timer)
{
	assert(timer->refcount);
	timer->refcount ++;
}

void
owl_timer_release(owl_timer_t *timer)
{
	assert(timer->refcount);
	if (--(timer->refcount) == 0)
		__owl_timer_free(timer);
}

void
owl_timer_cancel(owl_timer_t *timer)
{
	if (timer->state == OWL_TIMER_STATE_ACTIVE
	 || timer->state == OWL_TIMER_STATE_PAUSED
	 || timer->state == OWL_TIMER_STATE_CANCELLED) {
		timer->state = OWL_TIMER_STATE_CANCELLED;
		__owl_timer_unlink(timer);
		owl_timer_release(timer);
	}
}

void
owl_timer_pause(owl_timer_t *timer)
{
	/* silently ignore duplicate calls to pause a timer */
	if (timer->state == OWL_TIMER_STATE_PAUSED)
		return;

	if (timer->state == OWL_TIMER_STATE_ACTIVE) {
		struct timeval now;

		gettimeofday(&now, NULL);
		if (timercmp(&now, &timer->expires, <))
			timersub(&timer->expires, &now, &timer->runtime);
		else
			timerclear(&timer->runtime);
		timerclear(&timer->expires);

		timer->state = OWL_TIMER_STATE_PAUSED;
	}
}

void
owl_timer_unpause(owl_timer_t *timer)
{
	if (timer->state == OWL_TIMER_STATE_PAUSED) {
		struct timeval now;

		gettimeofday(&now, NULL);
		timeradd(&timer->runtime, &now, &timer->expires);
		timer->state = OWL_TIMER_STATE_ACTIVE;
	}
}

long
owl_timer_remaining(const owl_timer_t *timer)
{
	struct timeval now, delta;

	switch (timer->state) {
	case OWL_TIMER_STATE_ACTIVE:
		gettimeofday(&now, NULL);
		if (timercmp(&now, &timer->expires, <)) {
			timersub(&timer->expires, &now, &delta);
			return 1000 * delta.tv_sec + delta.tv_usec / 1000;
		}

		return 0;

	default:
		return 0;
	}
}

bool
owl_timer_is_expired(const owl_timer_t *timer)
{
	return timer->state == OWL_TIMER_STATE_EXPIRED || timer->state == OWL_TIMER_STATE_DEAD;
}

void
owl_timer_kill(owl_timer_t *timer)
{
	timer->state = OWL_TIMER_STATE_DEAD;
	timer->callback = NULL;

	__owl_timer_unlink(timer);
	owl_timer_release(timer);
}

static void
__owl_timer_mark_expired(owl_timer_t *timer)
{
	log_debug("Timer %u expired", timer->id);
	timer->state = OWL_TIMER_STATE_EXPIRED;
	timerclear(&timer->expires);

	/* Do /not/ invoke the callback yet - we may be deep inside
	 * some transport code, which may or may not be re-entrant.
	 * We do this at a later point, from owl_timer_list_reap()
	 */
}

void
owl_timer_list_insert(owl_timer_list_t *list, owl_timer_t *timer)
{
	assert(timerisset(&timer->expires));
	assert(timer->prev == NULL);
	__owl_timer_insert(&list->head, timer);
}

void
owl_timer_list_move(owl_timer_list_t *list, owl_timer_t *timer)
{
	__owl_timer_unlink(timer);
	__owl_timer_insert(&list->head, timer);
}

/*
 * Walk the list of timers, and update the owl_timeout_t to reflect the
 * point in time when the next timer expires.
 * If a timer has already expired, this will result in a timeout of 0,
 * and the respective time is moved to state OWL_TIMER_STATE_EXPIRED.
 */
void
owl_timer_list_update_timeout(owl_timer_list_t *list, owl_timeout_t *tmo)
{
	owl_timer_t *t;

	for (t = list->head; t; t = t->next) {
		/* If the timer's expiry time is in the past,
		 * owl_timeout_update() will return false
		 * and set tmo->expired = true;
		 */
		if (t->state == OWL_TIMER_STATE_ACTIVE
		 && !owl_timeout_update(tmo, &t->expires))
			__owl_timer_mark_expired(t);
	}
}

void
owl_timer_list_expire(owl_timer_list_t *list)
{
	owl_timeout_t tmo;

	owl_timeout_init(&tmo);
	owl_timer_list_update_timeout(list, &tmo);
}

void
owl_timer_list_reap(owl_timer_list_t *list, owl_timer_list_t *expired)
{
	owl_timer_t *t, *next;

	for (t = list->head; t; t = next) {
		next = t->next;

		if (t->state == OWL_TIMER_STATE_EXPIRED
		 || t->state == OWL_TIMER_STATE_CANCELLED) {
			log_debug("Reaping timer %u (state %d)", t->id, t->state);
			owl_timer_list_move(expired, t);
		}
	}
}

void
owl_timer_list_invoke(owl_timer_list_t *list)
{
	owl_timer_t *t;

	while ((t = list->head) != NULL) {
		if (t->state == OWL_TIMER_STATE_EXPIRED && t->callback) {
			log_debug("Invoking timer %u", t->id);
			t->callback(t, t->user_data);
		}

		owl_timer_kill(t);
	}
}


void
owl_timer_list_destroy(owl_timer_list_t *list)
{
	owl_timer_t *t;

	while ((t = list->head) != NULL)
		owl_timer_kill(t);
}

void
owl_timers_update_timeout(owl_timeout_t *tmo)
{
	owl_timer_list_update_timeout(&__global_timer_list, tmo);
}

void
owl_timers_run(void)
{
	owl_timer_list_t expired = { .head = NULL };
	owl_timeout_t timeout;

	/* Do another pass over the list, and catch timers that have
	 * expired since the last inspection.
	 *
	 * We do this because the usual approach is
	 *
	 *   owl_timers_update_timeout(...);
	 *   poll(..)
	 *   owl_timers_run();
	 *
	 * So we have to account for the fact that we spent some time
	 * inside poll()
	 */
	owl_timeout_init(&timeout);
	owl_timer_list_update_timeout(&__global_timer_list, &timeout);

	owl_timer_list_reap(&__global_timer_list, &expired);
	owl_timer_list_invoke(&expired);
	owl_timer_list_destroy(&expired);
}

void
owl_timeout_init(owl_timeout_t *tmo)
{
	gettimeofday(&tmo->now, NULL);
	timerclear(&tmo->until);
}

bool
owl_timeout_update(owl_timeout_t *tmo, const struct timeval *deadline)
{
	if (deadline->tv_sec == 0)
		return true;

	if (timercmp(&tmo->now, deadline, >=)) {
		tmo->until = tmo->now;
		return false; /* expired */
	}

	if (!timerisset(&tmo->until) || timercmp(deadline, &tmo->until, <))
		tmo->until = *deadline;

	return true;
}

long
owl_timeout_msec(const owl_timeout_t *tmo)
{
	struct timeval delta;
	long delta_msec;

	if (!timerisset(&tmo->until))
		return -1;

	timersub(&tmo->until, &tmo->now, &delta);

	/* If the timer has not expired, but the difference is less
	 * than one millisec, return 1 nevertheless to keep the poll
	 * loop from busy waiting */
	delta_msec = 1000 * delta.tv_sec + delta.tv_usec / 1000;
	if (delta_msec == 0 && timerisset(&delta))
		delta_msec = 1;

	return delta_msec;
}

struct timespec *
owl_timeout_timespec(const owl_timeout_t *tmo)
{
	static struct timespec value;
	struct timeval delta;

	if (!timerisset(&tmo->until))
		return NULL;

	timersub(&tmo->until, &tmo->now, &delta);
	value.tv_sec = delta.tv_sec;
	value.tv_nsec = delta.tv_usec * 1000;

	return &value;
}
