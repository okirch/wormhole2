/*
 * queue.c
 *
 * Simple send buffer management for sockets, ttys etc
 *
 *   Copyright (C) 2020 Olaf Kirch <okir@suse.de>
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include "queue.h"

#define QUEUE_MEM_POISON	1

static inline queue_entry_t *
queue_entry_new(buffer_t *bp)
{
	queue_entry_t *qe;

	qe = calloc(1, sizeof(*qe));
	if (bp == NULL)
		bp = buffer_alloc_write(QUEUE_ENTRY_SZ);
	qe->buf = bp;
	return qe;
}

static inline void
queue_entry_free(queue_entry_t *qe)
{
	if (qe->buf) {
		buffer_free(qe->buf);
		qe->buf = NULL;
	}

#if QUEUE_MEM_POISON
	memset(qe, 0x55, sizeof(*qe));
#endif
	free(qe);
}

queue_t *
queue_alloc(void)
{
	queue_t *q;

	q = calloc(1, sizeof(*q));
	return q;
}

void
queue_free(queue_t *q)
{
	queue_destroy(q);
	free(q);
}

void
queue_init(queue_t *q)
{
	memset(q, 0, sizeof(*q));
}

static inline void
queue_validate(const queue_t *q)
{
	const queue_entry_t *qe;
	unsigned int count = 0;

	for (qe = q->head; qe; qe = qe->next)
		count += buffer_available(qe->buf);
	assert(q->size == count);
	assert(q->size <= QUEUE_SZ);
}

void
queue_destroy(queue_t *q)
{
	queue_entry_t *qe;

	while ((qe = q->head) != NULL) {
		q->head = qe->next;
		q->size -= buffer_available(qe->buf);
		queue_entry_free(qe);
	}
}

static queue_entry_t *
queue_add_entry(queue_t *q, buffer_t *bp)
{
	queue_entry_t *qe, **pos;

	assert(q->size + QUEUE_ENTRY_SZ <= QUEUE_SZ);

	/* Find the list tail */
	for (pos = &q->head; (qe = *pos) != NULL; pos = &qe->next)
		;

	qe = queue_entry_new(bp);
	*pos = qe;
	return qe;
}

unsigned long
queue_available(const queue_t *q)
{
	return q->size;
}

unsigned long
queue_tailroom(const queue_t *q)
{
	return QUEUE_SZ - q->size;
}

bool
queue_full(const queue_t *q)
{
	return q->size == QUEUE_SZ;
}

bool
queue_append(queue_t *q, const void *p, size_t count)
{
	queue_entry_t *qe = NULL;

	queue_validate(q);

	if (count > queue_tailroom(q))
		return false;

	/* Find the tail of the queue */
	for (qe = q->head; qe && qe->next; qe = qe->next)
		;

	while (count) {
		unsigned int n;
		buffer_t *bp;

		if (qe == NULL || buffer_tailroom(qe->buf) == 0)
			qe = queue_add_entry(q, NULL);

		bp = qe->buf;

		if ((n = buffer_tailroom(bp)) > count)
			n = count;

		buffer_put(bp, p, n);
		p += n;

		q->size += n;
		count -= n;
	}

	return true;
}

void *
queue_peek(const queue_t *q, void *p, size_t count)
{
	const queue_entry_t *qe;
	void *result = p;

	queue_validate(q);

	if (count == 0)
		return p;

	if (count > q->size)
		return NULL;

	for (qe = q->head; qe && count; qe = qe->next) {
		const buffer_t *bp = qe->buf;
		unsigned int n;

		assert(qe);

		n = buffer_available(bp);
		if (n > count)
			n = count;

		if (p) {
			memcpy(p, buffer_read_pointer(bp), n);
			p += n;
		}

		count -= n;
	}

	if (count)
		log_fatal("queue_peek: not enough data in queue");

	return result;
}

buffer_t *
queue_peek_buffer(const queue_t *q, size_t count)
{
	buffer_t *bp = buffer_alloc_write(count);

	if (!queue_peek(q, buffer_write_pointer(bp), count)) {
		buffer_free(bp);
		return NULL;
	}

	__buffer_advance_tail(bp, count);
	return bp;
}

void *
queue_get(queue_t *q, void *p, size_t count)
{
	queue_entry_t *qe;
	void *result = p;

	queue_validate(q);

	if (count == 0)
		return p;

	if (count > q->size)
		return NULL;

	while (count && (qe = q->head) != NULL) {
		buffer_t *bp = qe->buf;
		unsigned int n;

		assert(qe);

		n = buffer_available(bp);
		if (n > count)
			n = count;

		if (!buffer_get(bp, p, n))
			log_error("%s: should not happen", __func__);
		p += n;

		q->size -= n;
		count -= n;

		if (buffer_available(bp) == 0) {
			q->head = qe->next;
			queue_entry_free(qe);
		}
	}

	if (count)
		log_fatal("queue_get: not enough data in queue");

	return result;
}

bool
queue_gets(queue_t *q, char *buffer, size_t size)
{
	queue_entry_t *qe;
	unsigned int pos;

	queue_validate(q);

	if (size == 0)
		return NULL;

	pos = 0;
	while ((qe = q->head) != NULL) {
		buffer_t *bp = qe->buf;
		int cc;

		assert(qe);

		while (pos + 1 < size) {
			if ((cc = buffer_getc(bp)) < 0)
				break; /* end of this buffer */
			buffer[pos++] = cc;
			if (cc == '\n')
				goto eol;
		}

		if (buffer_available(bp) == 0) {
			q->head = qe->next;
			queue_entry_free(qe);
		}
	}

eol:
	if (pos == 0)
		return NULL;

	buffer[pos] = '\0';
	q->size -= pos;
	return true;
}

buffer_t *
queue_get_buffer(queue_t *q, size_t count)
{
	buffer_t *bp = buffer_alloc_write(count);

	if (!queue_get(q, buffer_write_pointer(bp), count)) {
		buffer_free(bp);
		return NULL;
	}

	__buffer_advance_tail(bp, count);
	return bp;
}

bool
queue_skip(queue_t *q, size_t count)
{
	queue_entry_t *qe;

	queue_validate(q);

	if (count == 0)
		return NULL;

	while ((qe = q->head) != NULL) {
		buffer_t *bp = qe->buf;
		unsigned int n;

		n = buffer_available(bp);
		if (n > count)
			n = count;

		(void) buffer_skip(bp, n);
		q->size -= n;
		count -= n;

		if (buffer_available(bp) != 0)
			break;

		q->head = qe->next;
		queue_entry_free(qe);
	}

	return true;
}

bool
queue_transfer(queue_t *dstq, queue_t *srcq, size_t count)
{
	void *data;

	assert(queue_tailroom(dstq) >= count);
	assert(queue_available(srcq) >= count);

	data = alloca(count);
	if (!queue_get(srcq, data, count))
		return false;

        queue_append(dstq, data, count);
	return true;
}

bool
queue_transfer_buffer(queue_t *q, buffer_t *bp)
{
	unsigned int count = buffer_available(bp);

	queue_validate(q);

	if (count == 0) {
		buffer_free(bp);
		return true;
	}

	if (count > queue_tailroom(q))
		return false;

	q->size += count;
	queue_add_entry(q, bp);
	return true;
}

bool
queue_advance_head(queue_t *q, size_t count)
{
	queue_entry_t *qe;

	queue_validate(q);

	while (count) {
		unsigned int n;

		if (!(qe = q->head))
			return false;

		if ((n = buffer_available(qe->buf)) > count)
			n = count;

		buffer_skip(qe->buf, n);
		count -= n;

		assert(q->size >= n);
		q->size -= n;

		if (buffer_eof(qe->buf)) {
			q->head = qe->next;
			queue_entry_free(qe);
		}
	}

	return true;
}
