/*
 *
 *   Copyright (C) 2020-2021 Olaf Kirch <okir@suse.de>
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

#ifndef _TRACING_H
#define _TRACING_H

#include <stdbool.h>
#include <unistd.h>

extern void		(*__tracing_hook)(const char *fmt, ...);
extern void		(*__tracing_hook2)(const char *fmt, ...);
extern void		(*__tracing_hook3)(const char *fmt, ...);

#define trace(...) do { \
		if (__tracing_hook) \
			__tracing_hook(__VA_ARGS__); \
	} while (0)
#define trace2(...) do { \
		if (__tracing_hook2) \
			__tracing_hook2(__VA_ARGS__); \
	} while (0)
#define trace3(...) do { \
		if (__tracing_hook3) \
			__tracing_hook3(__VA_ARGS__); \
	} while (0)
#define notrace(...) do { \
	} while (0)

extern unsigned int	tracing_level;

extern bool		set_logfile(const char *filename);
extern void		set_syslog(const char *name, int facility);
extern void		tracing_increment_level(void);
extern void		tracing_set_level(unsigned int);

extern void		log_debug(const char *fmt, ...);
extern void		log_info(const char *fmt, ...);
extern void		log_warning(const char *fmt, ...);
extern void		log_error(const char *fmt, ...);
extern void		log_fatal(const char *fmt, ...);
extern void		logging_notify_raw_tty(bool);

static inline void
progress_indicate(char c)
{
	while (write(1, &c, 1) == 0);
}

#endif /* _TRACING_H */
