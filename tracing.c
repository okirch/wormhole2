/*
 * tracing.c
 *
 * Simple tracing and logging facilities
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

#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

/* For __get_logf() */
#include <unistd.h>
#include <fcntl.h>

#include "tracing.h"

unsigned int	tracing_level = 0;

void		(*__tracing_hook)(const char *fmt, ...);
void		(*__tracing_hook2)(const char *fmt, ...);
void		(*__tracing_hook3)(const char *fmt, ...);

static FILE *	logfile = NULL;
static bool	logging_to_tty = false;
static bool	logging_to_syslog = false;
static bool	logging_raw_tty = false;

static FILE *
__get_logf(void)
{
	if (logfile == NULL) {
		int fd = dup(2);

		fcntl(fd, F_SETFD, FD_CLOEXEC);
		logfile = fdopen(fd, "w");

		logging_to_tty = isatty(fd);
	}
	return logfile;
}

/*
 * Print a prefix to a log message. We squirrel away errno in case
 * the message format contains %m.
 */
static void
__log_prefix(const char *fmt, ...)
{
	int saved_errno = errno;
	va_list ap;

	va_start(ap, fmt);
	vfprintf(__get_logf(), fmt, ap);
	va_end(ap);

	errno = saved_errno;
}

static void
__log_format(const char *prefix, const char *fmt, va_list ap)
{
	FILE *f = __get_logf();
	int n;

	if (fmt == NULL)
		return;

	if (prefix)
		__log_prefix("%s: ", prefix);

	vfprintf(f, fmt, ap);

	/* When logging to a tty in raw mode, there is no automatic CRLF
	 * translation. fudge it. */
	n = strlen(fmt);
	if (n) {
		if (fmt[n-1] != '\n')
			fputc('\n', f);
		if (logging_raw_tty)
			fputc('\r', f);
	}

	fflush(f);
}

static void
__log_message(int level, const char *prefix, const char *fmt, va_list ap)
{
	if (logging_to_syslog) {
		/* LOG_EMERG indicates that this is a fatal error (for us) */
		if (level == LOG_EMERG)
			level = LOG_ERR;
		vsyslog(level, fmt, ap);
	} else {
		if (prefix == NULL) {
			switch (level) {
			case LOG_EMERG:
				prefix = "Fatal error";
				break;
			case LOG_ERR:
				prefix = "Error";
				break;
			case LOG_WARNING:
				prefix = "Warning";
				break;
			case LOG_INFO:
			case LOG_DEBUG:
			default:
				/* nothing */ ;
			}
		}
		__log_format(prefix, fmt, ap);
	}
}

void
log_debug(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__log_message(LOG_DEBUG, NULL, fmt, ap);
	va_end(ap);
}

void
log_debug_id(const char *id, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__log_message(LOG_DEBUG, id, fmt, ap);
	va_end(ap);
}

void
log_info(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__log_message(LOG_INFO, NULL, fmt, ap);
	va_end(ap);
}

void
log_warning(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__log_message(LOG_WARNING, NULL, fmt, ap);
	va_end(ap);
}

void
log_error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__log_message(LOG_ERR, NULL, fmt, ap);
	va_end(ap);
}

void
log_error_id(const char *id, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__log_message(LOG_ERR, id, fmt, ap);
	va_end(ap);
}

void
log_fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__log_message(LOG_EMERG, NULL, fmt, ap);
	va_end(ap);

	exit(1);
}

void
set_syslog(const char *name, int facility)
{
	if (facility < 0)
		facility = LOG_DAEMON;

	openlog(name, 0, facility);
	logging_to_syslog = true;
}

bool
set_logfile(const char *filename)
{
	if (logfile && logfile != stderr)
		fclose(logfile);
	logfile = NULL;

	printf("Setting logfile to %s\n", filename);
	if (filename && strcmp(filename, "-")) {
		logfile = fopen(filename, "w");
		if (logfile == NULL) {
			fprintf(stderr, "Unable to open logfile \"%s\": %m\n", filename);
			return false;
		}
		setlinebuf(logfile);
	} else {
		logfile = stderr;
	}

	return true;
}

static void
__tracing_update_hooks(void)
{
	__tracing_hook = NULL;
	__tracing_hook2 = NULL;
	__tracing_hook3 = NULL;

	switch (tracing_level) {
	default:
	case 3:
		__tracing_hook3 = log_debug;
	case 2:
		__tracing_hook2 = log_debug;
	case 1:
		__tracing_hook = log_debug;
		break;
	case 0:
		break;
	}
}

/*
 * Repeated calls to this function increase the verbosity level
 */
void
tracing_increment_level(void)
{
	tracing_level++;
	__tracing_update_hooks();
}

void
tracing_set_level(unsigned int level)
{
	tracing_level = level;
	__tracing_update_hooks();
}

void
logging_notify_raw_tty(bool on)
{
	trace("%s(%d)\n", __func__, on);
	logging_raw_tty = on;
}
