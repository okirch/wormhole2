/*
 * queue.h
 *
 *   Copyright (C) 2020-2023 Olaf Kirch <okir@suse.de>
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

#ifndef _QUEUE_H
#define _QUEUE_H

#include <stdlib.h>
#include <stdbool.h>
#include "bufparser.h"

#define QUEUE_ENTRY_SZ		1024
#define QUEUE_SZ		(64 * QUEUE_ENTRY_SZ)

typedef struct queue_entry {
	struct queue_entry *	next;
	buffer_t		buf;
} queue_entry_t;

typedef struct queue {
	unsigned long		size;
	queue_entry_t *		head;
} queue_t;

extern queue_t *	queue_alloc(void);
extern void		queue_free(queue_t *);
extern void		queue_init(queue_t *);
extern void		queue_destroy(queue_t *);
extern unsigned long	queue_available(const queue_t *);
extern unsigned long	queue_tailroom(const queue_t *);
extern bool		queue_full(const queue_t *);
extern bool		queue_append(queue_t *, const void *, size_t);
extern void *		queue_get(queue_t *q, void *p, size_t count);
extern buffer_t *	queue_get_buffer(queue_t *q, size_t count);
extern bool		queue_gets(queue_t *q, char *p, size_t size);
extern void *		queue_peek(const queue_t *q, void *p, size_t count);
extern buffer_t *	queue_peek_buffer(const queue_t *q, size_t count);
extern bool		queue_skip(queue_t *q, size_t count);
extern bool		queue_transfer(queue_t *dstq, queue_t *srcq, size_t count);
extern bool		queue_transfer_buffer(queue_t *dstq, buffer_t *bp);
extern bool		queue_advance_head(queue_t *q, size_t count);


#endif /* _QUEUE_H */

