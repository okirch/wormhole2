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

#include <sys/socket.h>
#include <sys/poll.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stdarg.h>
#include <errno.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>
#include <systemd/sd-bus-protocol.h>

#include "owl/bufparser.h"
#include "owl/queue.h"
#include "dbus-relay.h"

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

typedef struct dbus_pending_call dbus_pending_call_t;
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

struct dbus_pending_call {
	dbus_pending_call_t *	next;
	bool			timed_out;

	struct {
		uint32_t	seq;
		char *		sender;
		char *		destination;
	} downstream, upstream;
};


#ifdef ENABLE_MESSAGE_TRACING
# define trace_message		log_debug
#else
# define trace_message(fmt ...) do { } while (0)
#endif

static unsigned int
align8(unsigned int size)
{
	return (size + 7) & ~7U;
}

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

static bool
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

static bool
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

static void
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
			"%s %s; serial %u; flags 0x%x%s", verb, dbus_semicooked_message_type_to_string(msg->msg_type),
			msg->msg_seq, msg->msg_flags,
			strutil_dynstr_value(&ds));

	strutil_dynstr_destroy(&ds);
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

static void
__dbus_message_segment_begin(struct buffer_segment *where, buffer_t *bp)
{
	where->offset = bp->rpos;
}

static void
__dbus_message_segment_end(struct buffer_segment *where, buffer_t *bp)
{
	where->len = bp->rpos - where->offset;
}

static bool
__dbus_message_patch_begin(const struct buffer_segment *where, buffer_t *bp, buffer_t *orig)
{
	if (orig->rpos > where->offset)
		return false;

	if (!buffer_put_padding(bp, 4))
		return false;

	if (!buffer_copy(orig, where->offset - orig->rpos, bp))
		return false;

	return buffer_skip(orig, where->len);
}

static bool
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

	/* If we're not at the end of the header array, consume any padding between
	 * this header field and the next. */
	if (buffer_available(bp) && !buffer_consume_padding(bp, 4))
		return false;

	__dbus_message_segment_end(&var->where, bp);

	// log_debug("SEGMENT: %u/%u, value=%s", var->where.offset, var->where.len, var->value);
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

	// log_debug("SEGMENT: %u/%u, value=%u", var->where.offset, var->where.len, var->value);
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

static dbus_forwarding_port_t *
dbus_forwarding_port_new(const char *name)
{
	static unsigned int port_id = 1;
	dbus_forwarding_port_t *fwport;

	fwport = calloc(1, sizeof(*fwport));
	strutil_set(&fwport->name, name);
	fwport->seq = (port_id++) * 1000;

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
	if (remaining) {
		if (!buffer_put_padding(hdr, 4)
		 || !buffer_copy(orig_hdr, remaining, hdr))
			goto failed;
	}

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

	dbus_semicooked_message_display(fwport, "forwarding", msg);
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

static bool
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
					log_debug_id(fwd->name, "end forwarding");
					return;
				}
			}
		}

		/* FIXME: handle call forwarding timeouts */
	}
}
