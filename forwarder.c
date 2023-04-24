/*
 * DBus forwarding support
 *
 *   Copyright (C) 2023 Olaf Kirch <okir@suse.de>
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
 *
 * These are the actual forwarding routines that relay DBus messages.
 *
 * Note that we're copying all messages as-is for now; except that we need
 * to change some header fields, like serial, sender and destination
 */

#include <stdint.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <assert.h>
#include <stdarg.h>
#include <errno.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>
#include <systemd/sd-bus-protocol.h>

#include "owl/endpoint.h"
#include "owl/timers.h"
#include "dbus-relay.h"

#define DBUS_SYSTEM_BUS_SOCKET	"/run/dbus/system_bus_socket"

struct dbus_header {
	unsigned char		endian;
	unsigned char		msg_type;
	unsigned char		msg_flags;
	unsigned char		prot_major;
	uint32_t		payload_len;
	uint32_t		msg_serial;
};

enum {
	DBUS_HDR_FIELD_PATH = 1,
	DBUS_HDR_FIELD_INTERFACE,
	DBUS_HDR_FIELD_MEMBER,
	DBUS_HDR_FIELD_ERROR_NAME,
	DBUS_HDR_FIELD_REPLY_SERIAL,
	DBUS_HDR_FIELD_DESTINATION,
	DBUS_HDR_FIELD_SENDER,
	DBUS_HDR_FIELD_SIGNATURE,
};

enum {
	STATE_SEND_AUTH,
	STATE_AWAIT_AUTH_RESPONSE,
	STATE_SEND_BEGIN,
	STATE_STARTUP_SENDING,
	STATE_STARTUP_AWAIT_RESPONSE,
	STATE_RELAYING,
	STATE_SHUTTING_DOWN
};

typedef struct dbus_message	dbus_message_t;
typedef struct dbus_client	dbus_client_t;
typedef struct dbus_pending_call dbus_pending_call_t;
typedef struct dbus_sigrec	dbus_sigrec_t;
typedef struct dbus_call	dbus_call_t;

typedef const struct dbus_client_ops dbus_client_ops_t;

typedef struct dbus_semicooked_message dbus_semicooked_message_t;

static uint8_t			dbus_host_endianness = 'l';


struct dbus_forwarding_port {
	int			fd;
	char *			name;
	char *			bus_name;
	unsigned int		accepted_msg_types_mask;
	uint32_t		seq;

	dbus_forwarding_port_t *other;
	dbus_pending_call_t *	calls;

	queue_t *		sendq;
	queue_t *		recvq;

	dbus_semicooked_message_t *partial_msg;
};

struct dbus_forwarder {
	char *			name;

	dbus_forwarding_port_t *downstream;
	dbus_forwarding_port_t *upstream;
};

struct buffer_segment {
	unsigned int		offset, len;
};
struct dbus_header_string {
	char *			value;
	struct buffer_segment	where;
};
struct dbus_header_uint32 {
	uint32_t		value;
	struct buffer_segment	where;
};

struct dbus_semicooked_message {
	buffer_t *		buffer;

	uint32_t		msg_seq;
	buffer_t *		header;

	unsigned int		msg_payload_len;
	buffer_t *		msg_payload;

	uint8_t			msg_type;
	uint8_t			msg_flags;

	uint8_t			patch_sequence[16];
	struct dbus_header_uint32 reply_serial;
	struct dbus_header_string sender;
	struct dbus_header_string destination;
};


struct dbus_client {
	char *			debug_name;

	sd_bus *		h;

	uint8_t			endianness;
	int			state;
	unsigned int		startup_step;
	uint32_t		seq;

	struct {
		dbus_client_ops_t *ops;
		void *		data;
	} impl;

	char *			bus_name;
	char *			request_name;

	endpoint_t *		ep;
	dbus_pending_call_t *	pending;
	dbus_sigrec_t *		signal_handlers;
};

struct dbus_client_ops {
	struct dbus_startup_call *startup_sequence;

	void			(*connection_lost)(dbus_client_t *);
	void			(*process_registered_names)(dbus_client_t *, const char **names, unsigned int count);
	void			(*name_acquired)(dbus_client_t *, const char *);
	void			(*name_lost)(dbus_client_t *, const char *);
	void			(*name_owner_changed)(dbus_client_t *, const char *, const char *, const char *);
};

typedef int			dbus_timer_callback_fn_t(void *);
struct dbus_timer {
	unsigned long		initial_timeout_ms;
	unsigned long		current_timeout_ms;
	sd_event_source *	event_source;
	dbus_timer_callback_fn_t *callback;
	void *			userdata;
};


struct dbus_call {
	sd_bus_message *	(*build_call)(dbus_client_t *);
	bool			(*response)(dbus_client_t *, sd_bus_message *);
	bool			(*error)(dbus_client_t *, const sd_bus_error *);
};

typedef void (*dbus_response_handler_t)(dbus_client_t *dbus, dbus_pending_call_t *call, const dbus_message_t *msg);
typedef void (*dbus_signal_handler_t)(dbus_client_t *dbus, sd_bus_message *msg);

struct dbus_pending_call {
	dbus_pending_call_t *	next;

	struct {
		uint32_t	seq;
		char *		sender;
		char *		destination;
	} downstream, upstream;

	bool			timed_out;

	dbus_message_t *	msg;
	owl_timer_t *		timer;

	dbus_response_handler_t handler;
};

struct dbus_sigrec {
	dbus_sigrec_t *		next;
	char *			interface;
	char *			member;

	dbus_signal_handler_t	handler;
};

#ifdef ENABLE_MESSAGE_TRACING
# define trace_message		log_debug
# define trace_message_ep	endpoint_debug
#else
# define trace_message(fmt ...) do { } while (0)
# define trace_message_ep(ep, fmt...) do { } while (0)
#endif

static inline unsigned int
align_size_to(unsigned int size, unsigned int multiple)
{
	unsigned int over;

	over = size % multiple;
	if (over != 0)
		size += multiple - over;
	return size;
}

static inline unsigned int
align8(unsigned int size)
{
	return (size + 7) & ~7U;
}

static inline void
dbus_debug(dbus_client_t *dbus, const char *fmt, ...)
{
	char msgbuf[512];
	va_list ap;

	if (tracing_level == 0)
		return;

	va_start(ap, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
	va_end(ap);

	log_debug("%s: %s", dbus->debug_name, msgbuf);
}

#if 0
dbus_client_t *
dbus_client_new(const char *name, dbus_client_ops_t *ops, void *impl_data)
{
	dbus_client_t *dbus;

	dbus = calloc(1, sizeof(*dbus));
	strutil_set(&dbus->debug_name, name);
	dbus->impl.ops = ops;
	dbus->impl.data = impl_data;
	dbus->endianness = 'l';
	dbus->state = STATE_SEND_AUTH;
	dbus->seq = 1;

	return dbus;
}

void
dbus_client_free(dbus_client_t *dbus)
{
	dbus_sigrec_t *rec;

	if (dbus->h) {
		sd_bus_unref(dbus->h);
		dbus->h = NULL;
	}

	while ((rec = dbus->signal_handlers) != NULL) {
		dbus->signal_handlers = rec->next;
		dbus_sigrec_free(rec);
	}
}

static dbus_sigrec_t *
dbus_sigrec_new(const char *interface_name, const char *member_name, dbus_signal_handler_t handler)
{
	dbus_sigrec_t *sig;

	sig = calloc(1, sizeof(*sig));
	strutil_set(&sig->interface, interface_name);
	strutil_set(&sig->member, member_name);
	sig->handler = handler;
	return sig;
}

static void
dbus_sigrec_free(dbus_sigrec_t *sig)
{
	strutil_drop(&sig->interface);
	strutil_drop(&sig->member);
	free(sig);
}
#endif

static dbus_pending_call_t *
dbus_pending_call_new(uint32_t seq, const char *sender, const char *destination)
{
	dbus_pending_call_t *call;

	call = calloc(1, sizeof(*call));
	call->downstream.seq = seq;
	strutil_set(&call->downstream.sender, sender);
	strutil_set(&call->downstream.destination, destination);
	return call;
}

static void
dbus_pending_call_free(dbus_pending_call_t *call)
{
	strutil_drop(&call->downstream.sender);
	strutil_drop(&call->upstream.sender);
	free(call);
}

#if 0
static void
dbus_client_insert_call(dbus_client_t *dbus, dbus_pending_call_t *call)
{
	/* simple for now */
	call->next = dbus->pending;
	dbus->pending = call;
}

static dbus_pending_call_t *
dbus_client_find_unlink_call(dbus_client_t *dbus, uint32_t seq)
{
	dbus_pending_call_t **pos, *call;

	for (pos = &dbus->pending; (call = *pos) != NULL; pos = &call->next) {
		if (call->upstream.seq == seq) {
			*pos = call->next;
			call->next = NULL;
			break;
		}
	}

	return call;
}

static void
dbus_pending_call_timeout(owl_timer_t *timer, void *user_data)
{
	dbus_pending_call_t *call = user_data;

	log_debug("%s(%u)", __func__, call->upstream.seq);
	call->timed_out = true;
}

static inline void
dbus_client_expect_response(dbus_client_t *dbus, dbus_message_t *msg, dbus_response_handler_t handler)
{
	dbus_pending_call_t *call;

	if ((call = dbus_client_find_unlink_call(dbus, msg->msg_seq)) != NULL) {
		log_error("%s: duplicate message seq", __func__);
		dbus_pending_call_free(call);
	}

	call = dbus_pending_call_new(msg->msg_seq, handler);

	call->timer = owl_timer_create(3000);
	owl_timer_set_callback(call->timer, dbus_pending_call_timeout, call);
	owl_timer_hold(call->timer);

	log_debug("inserting call %u", call->seq);
	dbus_client_insert_call(dbus, call);
}

static void
dbus_process_message(dbus_client_t *dbus, const dbus_message_t *msg)
{
	dbus_pending_call_t *call;

	if (msg->msg_type == SD_BUS_MESSAGE_METHOD_RETURN) {
		if ((call = dbus_client_find_unlink_call(dbus, msg->reply_serial)) == NULL) {
			log_debug("cannot find pending call for seq %u", msg->reply_serial);
			return;
		}

		log_debug("Response for call %u", msg->reply_serial);
		call->handler(dbus, call, msg);
		dbus_pending_call_free(call);

		/* If we're in startup and there are no more pending calls,
		 * switch back to sending mode to execute the next step. */
		if (dbus->state == STATE_STARTUP_AWAIT_RESPONSE
		 && dbus->pending == NULL)
			dbus->state = STATE_STARTUP_SENDING;
	} else
	if (msg->msg_type == SD_BUS_MESSAGE_SIGNAL) {
#if 0
		dbus_sigrec_t *sig;

		dbus_debug(dbus, "received signal %s.%s()", msg->interface_name, msg->member_name);
		for (sig = dbus->signal_handlers; sig; sig = sig->next) {
			if (dbus_signal_handler_match(sig, msg)) {
				dbus_debug(dbus, "Processing %s signal", msg->member_name);
				sig->handler(dbus, NULL, msg);
			}
		}
#endif
	}
}
#endif

static inline void
__dbus_make_header(uint8_t *header, uint8_t msg_type, uint8_t msg_flags, uint32_t msg_seq)
{
	uint32_t *words;

	header[0] = dbus_host_endianness;
	header[1] = msg_type;
	header[2] = msg_flags;
	header[3] = 1;

	words = (uint32_t *) (header + 4);
	words[0] = 0;		/* body length */
	words[1] = msg_seq;
}

static inline bool
__dbus_begin_header(buffer_t *hdr, uint8_t msg_type, uint8_t msg_flags, uint32_t msg_seq)
{
	uint8_t fixed_header[12];

	__dbus_make_header(fixed_header, msg_type, msg_flags, msg_seq);
	return buffer_put(hdr, fixed_header, sizeof(fixed_header));
}

static inline bool
__dbus_patch_header(buffer_t *hdr, buffer_t *orig_hdr, uint32_t msg_seq)
{
	uint8_t fixed_header[12];
	uint32_t *words;

	if (!buffer_get(orig_hdr, fixed_header, sizeof(fixed_header)))
		return false;

	/* update the message serial, but leave everything else alone. */
	words = (uint32_t *) (fixed_header + 4);
	words[1] = msg_seq;

	return buffer_put(hdr, fixed_header, sizeof(fixed_header));
}

static inline bool
__dbus_finalize_header(buffer_t *hdr)
{
	uint32_t *hfa_len_pointer;

	/* The header field array starts right after the fixed header */
	hfa_len_pointer = (uint32_t *) (hdr->data + hdr->rpos + 12);
	*hfa_len_pointer = buffer_available(hdr) - 12 - 4;

	return buffer_put_padding(hdr, 8);
}

static dbus_semicooked_message_t *
dbus_semicooked_message_new(void)
{
	dbus_semicooked_message_t *msg;

	msg = calloc(1, sizeof(*msg));
	return msg;
}

#if 0
static dbus_semicooked_message_t *
dbus_semicooked_message_builder_new(dbus_client_t *dbus, uint8_t msg_type, unsigned int msg_flags)
{
	dbus_semicooked_message_t *msg;
	uint8_t fixed_header[12];

	msg = calloc(1, sizeof(*msg));
	msg->buffer = buffer_alloc_write(8192);
	msg->msg_seq = dbus->seq++;
	msg->msg_type = msg_type;

	/* Construct the fixed size header */
	__dbus_make_header(fixed_header, msg_type, msg_flags, msg->msg_seq);
	buffer_put(msg->buffer, fixed_header, sizeof(fixed_header));

	return msg;
}
#endif

static inline buffer_t *
dbus_semicooked_message_build_payload(dbus_semicooked_message_t *msg, size_t size_hint)
{
	if (msg->msg_payload == NULL)
		msg->msg_payload = buffer_alloc_write(size_hint? : 1024);
	return msg->msg_payload;
}

static void
dbus_semicooked_message_free(dbus_semicooked_message_t *msg)
{
	if (msg->buffer) {
		buffer_free(msg->buffer);
		msg->buffer = NULL;
	}

	if (msg->msg_payload) {
		buffer_free(msg->msg_payload);
		msg->msg_payload = NULL;
	}

	strutil_drop(&msg->sender.value);
	strutil_drop(&msg->destination.value);
//	strutil_drop(&msg->object_path);
//	strutil_drop(&msg->interface_name);
//	strutil_drop(&msg->member_name);
//	strutil_drop(&msg->error_name);
//	strutil_drop(&msg->signature);

	free(msg);
}

static const char *
dbus_semicooked_message_type_to_string(unsigned int type)
{
	static const char *	names[_SD_BUS_MESSAGE_TYPE_MAX] = {
		[SD_BUS_MESSAGE_METHOD_CALL] = "call",
		[SD_BUS_MESSAGE_METHOD_RETURN] = "response",
		[SD_BUS_MESSAGE_METHOD_ERROR] = "error",
		[SD_BUS_MESSAGE_SIGNAL] = "signal",
	};
	const char *name = NULL;

	if (type < _SD_BUS_MESSAGE_TYPE_MAX)
		name = names[type];
	if (name == NULL)
		return "unknown";
	return name;
}

static inline void
dbus_semicooked_message_display(const dbus_forwarding_port_t *fwport,  const char *verb, const dbus_semicooked_message_t *msg)
{
	struct strutil_dynstr ds = STRUTIL_DYNSTR_INIT;

	if (msg->sender.value)
		strutil_dynstr_appendf(&ds, "; sender=%s", msg->sender.value);
	if (msg->destination.value)
		strutil_dynstr_appendf(&ds, "; destination=%s", msg->destination.value);
#if 0
	if (msg->object_path)
		strutil_dynstr_appendf(&ds, "; path=%s", msg->object_path);
	if (msg->interface_name)
		strutil_dynstr_appendf(&ds, "; interface=%s", msg->interface_name);
	if (msg->member_name)
		strutil_dynstr_appendf(&ds, "; member=%s", msg->member_name);
	if (msg->error_name)
		strutil_dynstr_appendf(&ds, "; error=%s", msg->error_name);
#endif
	if (msg->reply_serial.value)
		strutil_dynstr_appendf(&ds, "; reply-serial=%u", msg->reply_serial.value);

	log_debug_id(fwport->name,
			"%s %s; seq %u; flags 0x%x%s", verb, dbus_semicooked_message_type_to_string(msg->msg_type),
			msg->msg_seq, msg->msg_flags,
			strutil_dynstr_value(&ds));

	strutil_dynstr_destroy(&ds);
}

static inline unsigned int
__dbus_get_type_alignment(unsigned char type)
{
	static unsigned char alignment_table[256] = {
	['y'] = 1,	/* byte */
	['n'] = 2,	/* int16 */
	['q'] = 2,	/* uint16 */
	['i'] = 4,	/* int32 */
	['u'] = 4,	/* uint32 */
	['x'] = 8,	/* int64 */
	['t'] = 8,	/* uint64 */
	['d'] = 8,	/* double */
	['s'] = 4,	/* string */
	['o'] = 4,	/* objct path */
	['g'] = 1,	/* signature */
	['a'] = 4,	/* array */
	['r'] = 8,	/* struct */
	['('] = 8,	/* struct */
	[')'] = 8,	/* struct */
	['v'] = 1,	/* variant */
	['e'] = 8,	/* dict */
	['{'] = 8,	/* dict */
	['}'] = 8,	/* dict */
	['h'] = 4,	/* unix_fd */
	};

	return alignment_table[type];
}

static bool
__dbus_message_put_u32(buffer_t *bp, uint32_t word)
{
	return buffer_put_padding(bp, 4)
	    && buffer_put(bp, &word, 4);
}

static bool
__dbus_message_put_string(buffer_t *bp, const char *value)
{
	unsigned int len;

	if (!value)
		value = "";
	len = strlen(value);

	return __dbus_message_put_u32(bp, len)
	    && buffer_put(bp, value, len + 1)
	    // && buffer_put_padding(bp, 4)
	;
}

#if 0
static bool
__dbus_message_put_signature(buffer_t *bp, const char *sig)
{
	unsigned int sig_len;

	if (sig == NULL)
		sig = "";

	sig_len = strlen(sig);
	if (sig_len > 255)
		return false;

	return __dbus_message_put_byte(bp, sig_len)
	 && buffer_put(bp, sig, sig_len + 1);
}
#endif

static inline bool
__dbus_message_put_string_array(buffer_t *bp, const char **values)
{
	uint32_t *len_ptr, bytes = 0;
	unsigned int values_wpos;
	const char *string;

	if (!buffer_put_padding(bp, 4))
		return false;

	len_ptr = (uint32_t *) buffer_write_pointer(bp);
	if (!buffer_put(bp, &bytes, 4))
		return false;

	values_wpos = bp->wpos;
	while ((string = *values++) != NULL) {
		if (!__dbus_message_put_string(bp, string))
			return false;
	}

	bytes = bp->wpos - values_wpos;
	*len_ptr = bytes;
	return true;
}

static inline void
__dbus_message_display_next(buffer_t *bp)
{
	const unsigned char *next = buffer_read_pointer(bp);

	log_debug("  %4u: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			  bp->rpos,
			  next[0], next[1], next[2], next[3],
			  next[4], next[5], next[6], next[7],
			  next[8], next[9], next[10], next[11],
			  next[12], next[13], next[14], next[15]);
}

static const char *
__dbus_message_get_signature_work(buffer_t *bp)
{
	static char sig_buf[256];
	uint8_t sig_len;

	if (!buffer_get_u8(bp, &sig_len)
	 || sig_len == 0)
		return NULL;

	if (!buffer_get(bp, sig_buf, sig_len + 1)
	 || sig_buf[sig_len] != '\0')
		return NULL;

	return sig_buf;
}

static bool
__dbus_message_check_signature(buffer_t *bp, const char *expect)
{
	const char *sig;

	if (!(sig = __dbus_message_get_signature_work(bp)))
		return false;

	if (strcmp(sig, expect))
		return false;

	return true;
}

#if 0
static bool
__dbus_message_get_signature(buffer_t *bp, char **var)
{
	const char *sig;

	if (!__dbus_message_check_signature(bp, "g"))
		return false;

	if (!(sig = __dbus_message_get_signature_work(bp)))
		return false;

	strutil_set(var, sig);
	return true;
}
#endif

static bool
__dbus_message_skip_signature(buffer_t *bp)
{
	if (!__dbus_message_check_signature(bp, "g"))
		return false;

	return !!__dbus_message_get_signature_work(bp);
}

static bool
__dbus_message_get_string(buffer_t *bp, char **var)
{
	uint32_t str_len;
	char *str = NULL;

	if (!buffer_consume_padding(bp, 4))
		return false;

	if (!buffer_get(bp, &str_len, 4))
		return false;

	str = malloc(str_len + 1);
	if (!buffer_get(bp, str, str_len + 1)
	 || str[str_len] != '\0') {
		free(str);
		return false;
	}

	strutil_drop(var);
	*var = str;

	return true;
}

static inline bool
__dbus_message_get_string_array(buffer_t *bp, struct strutil_array *result)
{
	uint32_t bytes, end;
	char *str = NULL;

	if (!buffer_consume_padding(bp, 4))
		return false;

	if (!buffer_get(bp, &bytes, 4))
		return false;

	end = bp->rpos + bytes;
	while (bp->rpos < end) {
		if (!__dbus_message_get_string(bp, &str))
			return false;

		if (bp->rpos > end)
			return false;

		strutil_array_append(result, str);
	}

	strutil_drop(&str);
	return true;
}

static inline void
__dbus_message_segment_begin(struct buffer_segment *where, buffer_t *bp)
{
	where->offset = bp->rpos;
}

static inline void
__dbus_message_segment_end(struct buffer_segment *where, buffer_t *bp)
{
	where->len = bp->rpos - where->offset;
}

static inline bool
__dbus_message_patch_begin(const struct buffer_segment *where, buffer_t *bp, buffer_t *orig)
{
	if (orig->rpos > where->offset)
		return false;

	if (!buffer_copy(orig, where->offset - orig->rpos, bp))
		return false;

	return buffer_skip(orig, where->len);
}

static inline bool
__dbus_message_patch_end(const struct buffer_segment *where, buffer_t *bp, buffer_t *orig)
{
	return true;
}

static bool
__dbus_message_header_get_string(buffer_t *bp, char field_type, struct dbus_header_string *var)
{
	char signature[2] = { field_type, 0 };

	if (!__dbus_message_check_signature(bp, signature))
		return false;

	__dbus_message_segment_begin(&var->where, bp);
	if (!__dbus_message_get_string(bp, &var->value))
		return false;
	__dbus_message_segment_end(&var->where, bp);
	return true;
}

static bool
__dbus_header_field_patch_string(buffer_t *hdr, buffer_t *orig_hdr, const struct dbus_header_string *var)
{
	if (!__dbus_message_patch_begin(&var->where, hdr, orig_hdr))
		return false;

	if (!__dbus_message_put_string(hdr, var->value))
		return false;

	return __dbus_message_patch_end(&var->where, hdr, orig_hdr);
}

static bool
__dbus_message_header_skip_string(buffer_t *bp, char field_type)
{
	char signature[2] = { field_type, 0 };
	char *dummy = NULL;

	if (!__dbus_message_check_signature(bp, signature))
		return false;

	if (!__dbus_message_get_string(bp, &dummy))
		return false;
	strutil_drop(&dummy);
	return true;
}

static bool
__dbus_message_header_get_uint32(buffer_t *bp, struct dbus_header_uint32 *var)
{
	if (!__dbus_message_check_signature(bp, "u"))
		return false;

	if (!buffer_consume_padding(bp, 4))
		return false;

	__dbus_message_segment_begin(&var->where, bp);
	if (!buffer_get(bp, &var->value, 4))
		return false;
	__dbus_message_segment_end(&var->where, bp);
	return true;
}

static bool
__dbus_header_field_patch_uint32(buffer_t *hdr, buffer_t *orig_hdr, const struct dbus_header_uint32 *var)
{
	if (!__dbus_message_patch_begin(&var->where, hdr, orig_hdr))
		return false;

	if (!buffer_put(hdr, &var->value, 4))
		return false;

	return __dbus_message_patch_end(&var->where, hdr, orig_hdr);
}

#if 0
static bool
__dbus_message_begin_header_field(buffer_t *bp, uint8_t field_type, const char *field_sig)
{
	if (!buffer_put_padding(bp, 4))
		return false;

	return __dbus_message_put_byte(bp, field_type)
	    && __dbus_message_put_signature(bp, field_sig);
}

static bool
__dbus_message_header_put_object_path(buffer_t *bp,  uint8_t field_type, const char *value)
{
	if (value == NULL)
		return true;

	if (!__dbus_message_begin_header_field(bp, field_type, "o"))
		return false;

	return __dbus_message_put_string(bp, value);
}

static bool
__dbus_message_header_put_string(buffer_t *bp,  uint8_t field_type, const char *value)
{
	if (value == NULL)
		return true;

	if (!__dbus_message_begin_header_field(bp, field_type, "s"))
		return false;

	return __dbus_message_put_string(bp, value);
}

static bool
__dbus_message_header_put_signature(buffer_t *bp,  uint8_t field_type, const char *value)
{
	if (value == NULL)
		return true;

	if (!__dbus_message_begin_header_field(bp, field_type, "g"))
		return false;

	return __dbus_message_put_signature(bp, value);
}
#endif

bool
dbus_semicooked_message_method_build_header(dbus_semicooked_message_t *msg)
{
	buffer_t *bp = msg->buffer;
	uint32_t *hfa_pointer, *hl_pointer;
	size_t hfa_offset;

	trace_message("%s(hdrlen=%u, payloadlen=%u)", __func__, buffer_available(bp), 
			msg->msg_payload? buffer_available(msg->msg_payload) : 0);

	/* header field array offset */
	hfa_offset = bp->wpos;
	hfa_pointer = buffer_write_pointer(bp);
	__buffer_advance_tail(bp, 4);

	/*
	if (!__dbus_message_header_put_object_path(bp, DBUS_HDR_FIELD_PATH, msg->object_path)
	 || !__dbus_message_header_put_string(bp, DBUS_HDR_FIELD_DESTINATION, msg->destination)
	 || !__dbus_message_header_put_string(bp, DBUS_HDR_FIELD_INTERFACE, msg->interface_name)
	 || !__dbus_message_header_put_string(bp, DBUS_HDR_FIELD_MEMBER, msg->member_name)
	 || !__dbus_message_header_put_signature(bp, DBUS_HDR_FIELD_SIGNATURE, msg->signature)
	 )
		return false;
		*/

	*hfa_pointer = bp->wpos - hfa_offset - 4;

	/* stick the message body length into the fixed header */
	hl_pointer = (uint32_t *) (bp->data + bp->rpos + 4);
	if (msg->msg_payload != NULL) {
		*hl_pointer = buffer_available(msg->msg_payload);
	} else {
		*hl_pointer = 0;
	}

	/* pad out the header to an 8 byte boundary */
	if (!buffer_put_padding(bp, 8))
		return false;

	return true;
}

static inline bool
dbus_semicooked_message_transmit(endpoint_t *ep, queue_t *q, dbus_semicooked_message_t *msg)
{
	buffer_t *bp;

	if (!dbus_semicooked_message_method_build_header(msg))
		return false;

#ifdef notyet
	if (msg->buffer) {
		queue_transfer_buffer(q, msg->buffer);
		msg->buffer = NULL;
	}
#else
	if ((bp = msg->buffer) != NULL)
		queue_append(q, buffer_read_pointer(bp), buffer_available(bp));
	if ((bp = msg->msg_payload) != NULL)
		queue_append(q, buffer_read_pointer(bp), buffer_available(bp));
#endif
	return true;
}

/*
 * Message parsing
 */
static bool
dbus_semicooked_message_parse_header(buffer_t *hdr, dbus_semicooked_message_t *msg)
{
	unsigned char fixed_header[12 + 4];	/* fixed header + header field array length */
	buffer_t hdr_copy;
	unsigned int npatch = 0;

	/* We use a copy of the header, rather than the header itself, so that the rpos/wpos
	 * fields of the buffer remain intact for later patching. */
	hdr_copy = *hdr;
	hdr = &hdr_copy;

	if (!buffer_get(hdr, fixed_header, sizeof(fixed_header)))
		return false;

	msg->msg_type = fixed_header[1];
	msg->msg_flags = fixed_header[2];
	msg->msg_seq = *(uint32_t *) (fixed_header + 8);

	while (buffer_available(hdr)) {
		uint8_t field_type;

		// __dbus_message_display_next(hdr);

		/* This does not happen normally, only maliciously crafted messages
		 * would have more than one field of each type. */
		if (npatch + 2 >= sizeof(msg->patch_sequence))
			return false;

		if (!buffer_consume_padding(hdr, 8))
			return false;

		buffer_get_u8(hdr, &field_type);

		switch (field_type) {
		case DBUS_HDR_FIELD_PATH:
			if (!__dbus_message_header_skip_string(hdr, 'o'))
				return false;
			break;

		case DBUS_HDR_FIELD_INTERFACE:
			if (!__dbus_message_header_skip_string(hdr, 's'))
				return false;
			break;

		case DBUS_HDR_FIELD_MEMBER:
			if (!__dbus_message_header_skip_string(hdr, 's'))
				return false;
			break;

		case DBUS_HDR_FIELD_ERROR_NAME:
			if (!__dbus_message_header_skip_string(hdr, 's'))
				return false;
			break;

		case DBUS_HDR_FIELD_SIGNATURE:
			if (!__dbus_message_skip_signature(hdr))
				return false;
			break;

		case DBUS_HDR_FIELD_REPLY_SERIAL:
			if (!__dbus_message_header_get_uint32(hdr, &msg->reply_serial))
				return false;
			msg->patch_sequence[npatch++] = field_type;
			break;

		case DBUS_HDR_FIELD_DESTINATION:
			if (!__dbus_message_header_get_string(hdr, 's', &msg->destination))
				return false;
			msg->patch_sequence[npatch++] = field_type;
			break;

		case DBUS_HDR_FIELD_SENDER:
			if (!__dbus_message_header_get_string(hdr, 's', &msg->sender))
				return false;
			msg->patch_sequence[npatch++] = field_type;
			break;

		default:
			log_error("unsupported header field %u", field_type);
			return false;
		}
	}

	msg->patch_sequence[npatch] = 0;
	return true;
}

static bool
__dbus_get_header(dbus_semicooked_message_t *msg, queue_t *q)
{
	unsigned char fixed_header[12 + 4];	/* fixed header + header field array length */
	uint32_t msg_seq, payload_len, header_len;
	uint32_t unaligned_header_size, total_header_size;

	if (!queue_peek(q, fixed_header, sizeof(fixed_header)))
		return false;

	if (fixed_header[0] != dbus_host_endianness)
		log_fatal("bad endianness %c", fixed_header[0]);

	if (fixed_header[3] != 1)
		log_fatal("bad protocol major version %u", fixed_header[3]);

	memcpy(&payload_len, &fixed_header[4], 4);
	memcpy(&msg_seq, &fixed_header[8], 4);
	memcpy(&header_len, &fixed_header[12], 4);

	unaligned_header_size = sizeof(fixed_header) + header_len;
	total_header_size = align8(sizeof(fixed_header) + header_len);

	msg->header = queue_get_buffer(q, total_header_size);
	if (msg->header == NULL)
		return false;

	/* truncate buffer */
	{
		buffer_t *hdr = msg->header;

		assert(hdr->rpos + total_header_size == hdr->wpos);
		hdr->wpos = hdr->rpos + unaligned_header_size;
	}

	if (!dbus_semicooked_message_parse_header(msg->header, msg)) {
		/* should be destructive */
		log_fatal("unable to parse dbus header");
	}

	msg->msg_payload_len = payload_len;
	return true;
}

static bool
__dbus_get_payload(dbus_semicooked_message_t *msg, queue_t *q)
{
	/* Now, grab the payload.
	 * Note, there never seems to be padding after the end of the payload. So
	 * if the payload ends at stream position 91, then the next header will follow
	 * immediately.
	 */
	if (!(msg->msg_payload = queue_get_buffer(q, msg->msg_payload_len)))
		return false;

	return true;
}

#if 0
static dbus_semicooked_message_t *
dbus_handle_incoming(dbus_forwarding_port_t *fwport, queue_t *q)
{
	unsigned char fixed_header[12 + 4];	/* fixed header + header field array length */
	uint32_t msg_seq, payload_len, header_len, payload_alignment, total_msg_size, total_header_size;
	dbus_semicooked_message_t *msg;
	buffer_t *hdr;

	if (!queue_peek(q, fixed_header, sizeof(fixed_header)))
		return NULL;

	if (fixed_header[0] != dbus_host_endianness)
		log_fatal("bad endianness %c", fixed_header[0]);

	if (fixed_header[3] != 1)
		log_fatal("bad protocol major version %u", fixed_header[3]);

	memcpy(&payload_len, &fixed_header[4], 4);
	memcpy(&msg_seq, &fixed_header[8], 4);
	memcpy(&header_len, &fixed_header[12], 4);

	trace_message_ep(ep, "message seq %u: header_len %u payload_len %u", msg_seq, header_len, payload_len);

	if (!(hdr = queue_peek_buffer(q, sizeof(fixed_header) + header_len)))
		return NULL; /* not yet complete */

	msg = dbus_semicooked_message_new();
	if (!dbus_semicooked_message_parse_header(hdr, msg)) {
		/* should be destructive */
		log_fatal("unable to parse dbus header");
		return NULL;
	}

	buffer_free(hdr);

	total_header_size = align8(sizeof(fixed_header) + header_len);
	payload_alignment = 0;
	if (true) {
		unsigned int over;

		over = (sizeof(fixed_header) + header_len) % 8;
		if (over != 0)
			payload_alignment = 8 - over;
	}

	total_msg_size = total_header_size + payload_len;

	/* Make sure that we have the complete message sitting in the queue before
	 * we proceed.
	 */
	if (q->size < total_msg_size) {
		// dbus_debug(dbus, "incomplete message, need %u bytes", total_msg_size);
		dbus_semicooked_message_free(msg);
		return NULL;
	}

	/* Just skip over the header, we've processed it already */
	if (!queue_skip(q, total_header_size))
		log_fatal("bug in %s", __func__);

	/* Now, grab the payload.
	 * Note, there never seems to be padding after the end of the payload. So
	 * if the payload ends at stream position 91, then the next header will follow
	 * immediately.
	 */
	if (!(msg->msg_payload = queue_get_buffer(q, payload_len))) {
		/* This should not happen, as we've made sure we have the whole message
		 * sitting in the queue. */
		log_fatal("bug in %s", __func__);
	}

	// dbus_debug(dbus, "Processed complete message");
	return msg;
}

static dbus_semicooked_message_t *
dbus_semicooked_message_dissect(dbus_client_t *dbus, endpoint_t *ep, queue_t *q)
{
	unsigned char fixed_header[12 + 4];	/* fixed header + header field array length */
	uint32_t msg_seq, payload_len, header_len, payload_alignment, total_msg_size;
	dbus_semicooked_message_t *msg;
	buffer_t *hdr;

	if (!queue_peek(q, fixed_header, sizeof(fixed_header)))
		return NULL;

	if (fixed_header[0] != dbus->endianness) {
		/* should be destructive */
		endpoint_error(ep, "bad endianness %c", fixed_header[0]);
		return NULL;
	}

	if (fixed_header[3] != 1) {
		/* should be destructive */
		endpoint_error(ep, "bad protocol major version %u", fixed_header[3]);
		return NULL;
	}

	memcpy(&payload_len, &fixed_header[4], 4);
	memcpy(&msg_seq, &fixed_header[8], 4);
	memcpy(&header_len, &fixed_header[12], 4);

	trace_message_ep(ep, "message seq %u: header_len %u payload_len %u", msg_seq, header_len, payload_len);

	if (!(hdr = queue_peek_buffer(q, sizeof(fixed_header) + header_len)))
		return NULL; /* not yet complete */

	msg = dbus_semicooked_message_new();
	if (!dbus_semicooked_message_parse_header(hdr, msg)) {
		/* should be destructive */
		endpoint_error(ep, "unable to parse dbus header");
		return NULL;
	}

	buffer_free(hdr);

	payload_alignment = 0;
	if (true) {
		unsigned int over;

		over = (sizeof(fixed_header) + header_len) % 8;
		if (over != 0)
			payload_alignment = 8 - over;
	}

	total_msg_size = sizeof(fixed_header) + header_len + payload_alignment + payload_len;

	/* Make sure that we have the complete message sitting in the queue before
	 * we proceed.
	 */
	if (q->size < total_msg_size) {
		dbus_debug(dbus, "incomplete message, need %u bytes", total_msg_size);
		dbus_semicooked_message_free(msg);
		return NULL;
	}

	/* Just skip over the header, we've processed it already */
	if (!queue_skip(q, sizeof(fixed_header) + header_len + payload_alignment)) {
		log_fatal("bug in %s", __func__);
	}

	// __dbus_message_display_next(&q->head->buf);

	/* Now, grab the payload.
	 * Note, there never seems to be padding after the end of the payload. So
	 * if the payload ends at stream position 91, then the next header will follow
	 * immediately.
	 */
	if (!(msg->msg_payload = queue_get_buffer(q, payload_len))) {
		/* This should not happen, as we've made sure we have the whole message
		 * sitting in the queue. */
		log_fatal("bug in %s", __func__);
	}

	// dbus_debug(dbus, "Processed complete message");
	return msg;
}
#endif

static dbus_forwarding_port_t *
dbus_forwarding_port_new(const char *name)
{
	dbus_forwarding_port_t *fwport;

	fwport = calloc(1, sizeof(*fwport));
	strutil_set(&fwport->name, name);
	fwport->seq = 1;

	fwport->sendq = queue_alloc();
	fwport->recvq = queue_alloc();

	return fwport;
}

static void
dbus_forwarding_port_accept_msg_type(dbus_forwarding_port_t *fwport, unsigned int type)
{
	if (type >= _SD_BUS_MESSAGE_TYPE_MAX)
		return;

	log_debug_id(fwport->name, "accept msg type %s", dbus_semicooked_message_type_to_string(type));
	fwport->accepted_msg_types_mask |= (1 << type);
}

static dbus_pending_call_t *
dbus_forwarder_create_call_record(dbus_forwarding_port_t *fwport, dbus_semicooked_message_t *msg)
{
	dbus_pending_call_t *call;

	call = dbus_pending_call_new(msg->msg_seq, msg->sender.value, msg->destination.value);

	if (msg->destination.value[0] == ':') {
		log_error("Bad, we should patch the destination, too");
	}

	call->next = fwport->calls;
	fwport->calls = call;

	log_debug_id(fwport->name, "created call record for msg %u", msg->msg_seq);

	return call;
}

static dbus_pending_call_t *
dbus_forwarder_find_call_record(dbus_forwarding_port_t *fwport, dbus_semicooked_message_t *msg)
{
	dbus_pending_call_t **pos, *call;

	for (pos = &fwport->calls; (call = *pos) != NULL; pos = &call->next) {
		if (call->upstream.seq == msg->reply_serial.value) {
			*pos = call->next;
			call->next = NULL;
			break;
		}
	}

	return call;
}

static buffer_t *
dbus_build_patched_header(dbus_semicooked_message_t *msg)
{
	buffer_t *hdr, orig_hdr_copy, *orig_hdr;
	unsigned int npatch = 0, fid, remaining;

	hdr = buffer_alloc_write(2048);
	orig_hdr_copy = *(msg->header);
	orig_hdr = &orig_hdr_copy;

	/* Construct the fixed size header */
	if (!__dbus_patch_header(hdr, orig_hdr, msg->msg_seq))
		goto failed;

	/* start of header field array. Once we're done with writing the patched header,
	 * we need to update the array length word. */
	__buffer_advance_tail(hdr, 4);
	(void) buffer_skip(orig_hdr, 4);

	while ((fid = msg->patch_sequence[npatch++]) != 0) {
		bool ok = false;

		switch (fid) {
		case DBUS_HDR_FIELD_REPLY_SERIAL:
			ok = __dbus_header_field_patch_uint32(hdr, orig_hdr, &msg->reply_serial);
			break;

		case DBUS_HDR_FIELD_SENDER:
			ok = __dbus_header_field_patch_string(hdr, orig_hdr, &msg->sender);
			break;

		case DBUS_HDR_FIELD_DESTINATION:
			ok = __dbus_header_field_patch_string(hdr, orig_hdr, &msg->destination);
			break;

		default:
			log_error("invalid field %u in %s", fid, __func__);
			goto failed;
		}

		if (!ok)
			goto failed;
	}

	remaining = buffer_available(orig_hdr);
	if (!buffer_copy(orig_hdr, remaining, hdr))
		goto failed;

	/* Set the correct length for the header field array, and pad out the header to
	 * a multiple of 8 */
	if (!__dbus_finalize_header(hdr))
		goto failed;

	return hdr;

failed:
	buffer_free(hdr);
	return NULL;
}

static bool
dbus_forwarder_xmit(dbus_forwarding_port_t *fwport, buffer_t *hdr, buffer_t *body)
{
	/* We should really insert the buffers into the queue here, rather than
	 * copying them */
	return queue_transfer_buffer(fwport->sendq, hdr)
	    && queue_transfer_buffer(fwport->sendq, body);
}

static bool
dbus_forwarder_process_incoming(dbus_forwarding_port_t *fwport, dbus_semicooked_message_t *msg)
{
	unsigned int mask;

	/* Check whether we accept this message type on this port */
	mask = fwport->accepted_msg_types_mask;
	if (mask && !(mask & (1 << msg->msg_type))) {
		log_debug_id(fwport->name, "unexpected message type %u", msg->msg_type);
		return false;
	}

	/*
	   If it's a call
	 */

	if (msg->sender.value == NULL) {
		log_error_id(fwport->name, "Message lacks a sender");
		return false;
	}

	/* Check destination:
	 *  - empty destination is okay for signals, refused otherwise.
	 *  - if the destination is not our bus_name, leave it as-is
	 *  - if the destination matches our bus_name
	 *     if it's a signal, drop it
	 *     otherwise, clear the destination and let the outgoing code
	 *     set it to the caller's bus_name
	 */
	if (msg->destination.value == NULL) {
		if (msg->msg_type != SD_BUS_MESSAGE_SIGNAL) {
			log_error_id(fwport->name, "Message lacks a destination");
			return false;
		}
	} else
	if (!strcmp(msg->destination.value, fwport->bus_name)) {
		strutil_drop(&msg->destination.value);

		/* Drop unicast signals to our bus name */
		if (msg->msg_type == SD_BUS_MESSAGE_SIGNAL) {
			log_debug_id(fwport->name, "dropping unicast signal to myself");
			return false;
		}
	}

	/*
	   If it's a reply or an error:
	    - look for matching call
	    - if none exists, quietly drop the message
	    - else, set msg->in_response_to;
	    - drop the call record
	 */
	if (msg->msg_type == SD_BUS_MESSAGE_METHOD_RETURN
	 || msg->msg_type == SD_BUS_MESSAGE_METHOD_ERROR) {
		dbus_pending_call_t *call;

		if (!(call = dbus_forwarder_find_call_record(fwport, msg))) {
			log_debug("No matching call record for msg %u", msg->reply_serial.value);
			return false;
		}

		msg->reply_serial.value = call->downstream.seq;
		if (call->downstream.destination)
			strutil_set(&msg->sender.value, call->downstream.destination);
		strutil_set(&msg->destination.value, call->downstream.sender);

		dbus_pending_call_free(call);
	}

	/*
	   Check the destination: it should be for one of my registered bus names
	 */

#if 0
	/* If the sender of the incoming message is a local bus name :x.y,
	 * reset it, too */
	if (msg->sender.value[0] == ':')
		strutil_drop(&msg->sender.value);
#endif

	return true;
}

static bool
dbus_forwarder_process_outgoing(dbus_forwarding_port_t *fwport, dbus_semicooked_message_t *msg)
{
	dbus_pending_call_t *call = NULL;
	buffer_t *new_hdr, *body;

	/*
	   If it's a call
	    - unless msg_flags has NO_REPLY_EXPECTED (0x01) set, create a pending_call record
	    - pending_call record:
	    	- map original sender to my bus_name, record orig_sender
	   If it's a reply or error:
	    - patch reply_serial from msg->in_response_to
	 */
	if (msg->msg_type == SD_BUS_MESSAGE_METHOD_CALL) {
		if (!(msg->msg_flags & 0x01)) {
			/* reply expected */
			call = dbus_forwarder_create_call_record(fwport, msg);
		}
	} else
	if (msg->msg_type == SD_BUS_MESSAGE_SIGNAL) {
		/* Only forward broadcast signals */
		if (msg->destination.value != NULL)
			return false;
	}

	/* Set a new sequence number. */
	msg->msg_seq = fwport->seq++;

	/* Always override the sender name with our bus name */
	strutil_set(&msg->sender.value, fwport->bus_name);

	if (call) {
		call->upstream.seq = msg->msg_seq;
		strutil_set(&call->upstream.sender, msg->sender.value);
	}

	dbus_semicooked_message_display(fwport, "sending", msg);
	new_hdr = dbus_build_patched_header(msg);

	body = msg->msg_payload;
	msg->msg_payload = NULL;

	return dbus_forwarder_xmit(fwport, new_hdr, body);
}

static bool
dbus_queue_recv(queue_t *q, int fd)
{
	unsigned char buffer[65536];
	int r;

again:
	r = recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT);
	if (r < 0) {
		if (errno == EINTR)
			goto again;

		if (errno == EWOULDBLOCK || errno == EAGAIN)
			return true;

		log_error("receive error on socket: %m");
		return false;
	}

	if (r == 0) {
		log_debug("peer closed connection");
		return false;
	}

	return queue_append(q, buffer, r);
}

static bool
dbus_queue_xmit(queue_t *q, int fd)
{
	while (q->head) {
		buffer_t *bp = &q->head->buf;
		int sent, count;

		count = buffer_available(bp);
		assert(count);

		sent = send(fd, buffer_read_pointer(bp), count, MSG_DONTWAIT);
		if (sent < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;

			log_error("send error on socket: %m");
			return false;
		}

		(void) queue_advance_head(q, sent);
	}

	return true;
}

static bool
dbus_forwarder_recv(dbus_forwarding_port_t *fwport)
{
	queue_t *q = fwport->recvq;

	/* Receive data from socket and push to recvq */
	if (!dbus_queue_recv(q, fwport->fd))
		return false;

	while (q->size) {
		dbus_semicooked_message_t *msg;

		if (fwport->partial_msg == NULL)
			fwport->partial_msg = dbus_semicooked_message_new();
		msg = fwport->partial_msg;

		if (msg->header == NULL && !__dbus_get_header(msg, q))
			break; /* incomplete header */

		if (!__dbus_get_payload(msg, q))
			break; /* incomplete payload */

		dbus_semicooked_message_display(fwport, "received", msg);
		if (!dbus_forwarder_process_incoming(fwport, msg)) {
			log_debug_id(fwport->name, "dropping message %u", msg->msg_seq);
		} else {
			dbus_forwarder_process_outgoing(fwport->other, msg);
		}

		dbus_semicooked_message_free(msg);
		fwport->partial_msg = NULL;
	}

	return true;
}

static inline bool
dbus_forwarding_port_poll(dbus_forwarding_port_t *fwport, struct pollfd *p, dbus_forwarding_port_t **port_p)
{
	*port_p = fwport;
	p->events = 0;
	p->fd = fwport->fd;

	if (queue_available(fwport->sendq))
		p->events |= POLLOUT;
	if (queue_tailroom(fwport->recvq))
		p->events |= POLLIN;

	return !!p->events;
}

static bool
dbus_forwarding_port_doio(dbus_forwarding_port_t *fwport, struct pollfd *p)
{
	// log_debug_id(fwport->name, "%s(revents=0x%x)", __func__, p->revents);
	if ((p->revents & POLLOUT) && !dbus_queue_xmit(fwport->sendq, fwport->fd))
		return false;

	if ((p->revents & (POLLIN | POLLHUP | POLLERR)) && !dbus_forwarder_recv(fwport))
		return false;

	return true;
}

dbus_forwarder_t *
dbus_forwarder_new(const char *name)
{
	dbus_forwarder_t *fwd;
	char namebuf[64];

	fwd = calloc(1, sizeof(*fwd));
	strutil_set(&fwd->name, name);

	snprintf(namebuf, sizeof(namebuf), "%s:upstream", name);
	fwd->upstream = dbus_forwarding_port_new(namebuf);
	dbus_forwarding_port_accept_msg_type(fwd->upstream, SD_BUS_MESSAGE_METHOD_RETURN);
	dbus_forwarding_port_accept_msg_type(fwd->upstream, SD_BUS_MESSAGE_METHOD_ERROR);
	dbus_forwarding_port_accept_msg_type(fwd->upstream, SD_BUS_MESSAGE_SIGNAL);

	snprintf(namebuf, sizeof(namebuf), "%s:downstream", name);
	fwd->downstream = dbus_forwarding_port_new(namebuf);
	dbus_forwarding_port_accept_msg_type(fwd->downstream, SD_BUS_MESSAGE_METHOD_CALL);

	fwd->upstream->other = fwd->downstream;
	fwd->downstream->other = fwd->upstream;

	return fwd;
}

dbus_forwarding_port_t *
dbus_forwarder_get_upstream(dbus_forwarder_t *fwd)
{
	return fwd->upstream;
}

dbus_forwarding_port_t *
dbus_forwarder_get_downstream(dbus_forwarder_t *fwd)
{
	return fwd->downstream;
}

void
dbus_forwarding_port_set_bus_name(dbus_forwarding_port_t *fwport, const char *bus_name)
{
	log_debug_id(fwport->name, "bus_name=%s", bus_name);
	strutil_set(&fwport->bus_name, bus_name);
}

void
dbus_forwarding_port_set_socket(dbus_forwarding_port_t *fwport, int fd)
{
	log_debug_id(fwport->name, "socket=%d", fd);
	fwport->fd = fd;
}

void
dbus_forwarder_eventloop(dbus_forwarder_t *fwd)
{
	dbus_forwarding_port_t *fwport[2];
	struct pollfd pfd[2];

	log_debug_id(fwd->name, "entering forwarding event loop");
	while (true) {
		int nfds = 0, i, r;

		if (dbus_forwarding_port_poll(fwd->downstream, pfd + nfds, fwport + nfds))
			nfds++;
		if (dbus_forwarding_port_poll(fwd->upstream, pfd + nfds, fwport + nfds))
			nfds++;

		if (nfds == 0) {
			log_error_id(fwd->name, "%s: should not happen", __func__);
			return;
		}

		r = poll(pfd, nfds, 1000);
		if (r != 0) {
			for (i = 0; i < nfds; ++i) {
				if (!dbus_forwarding_port_doio(fwport[i], &pfd[i])) {
					log_error("end forwarding");
					return;
				}
			}
		}

		/* FIXME: handle call forwarding timeouts */
	}
}
