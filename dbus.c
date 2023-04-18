#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stdarg.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>

#include "owl/endpoint.h"
#include "owl/timers.h"

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
	DBUS_MSG_TYPE_INVALID = 0,
	DBUS_MSG_TYPE_METHOD_CALL,
	DBUS_MSG_TYPE_METHOD_RETURN,
	DBUS_MSG_TYPE_ERROR,
	DBUS_MSG_TYPE_SIGNAL,

	__DBUS_MSG_TYPE_MAX
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
typedef struct dbus_bridge_port	dbus_bridge_port_t;
typedef struct dbus_service_proxy dbus_service_proxy_t;
typedef struct dbus_pending_call dbus_pending_call_t;
typedef struct dbus_sigrec	dbus_sigrec_t;
typedef struct dbus_call	dbus_call_t;
typedef struct dbus_timer	dbus_timer_t;

typedef const struct dbus_client_ops dbus_client_ops_t;

extern bool			dbus_bridge_port_acquire_name(dbus_bridge_port_t *port, const char *name);
extern void			dbus_bridge_port_event_name_lost(dbus_bridge_port_t *port, const char *name);
extern void			dbus_bridge_port_event_name_acquired(dbus_bridge_port_t *port, const char *name);
static bool			dbus_service_proxy_connect(dbus_service_proxy_t *proxy, dbus_bridge_port_t *port);

typedef void			dbus_startup_fn_t(dbus_client_t *, endpoint_t *, queue_t *);
struct dbus_startup_call {
	const char *		name;
	dbus_startup_fn_t *	queue_fn;
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

struct dbus_message {
	buffer_t *		buffer;

	uint32_t		msg_seq;

	uint8_t			msg_type;
	uint8_t			msg_flags;
	uint32_t		reply_serial;
	char *			sender;
	char *			destination;
	char *			object_path;
	char *			interface_name;
	char *			member_name;
	char *			error_name;

	char *			signature;
	buffer_t *		msg_payload;
};

typedef void (*dbus_response_handler_t)(dbus_client_t *dbus, dbus_pending_call_t *call, const dbus_message_t *msg);
typedef void (*dbus_signal_handler_t)(dbus_client_t *dbus, sd_bus_message *msg);

struct dbus_pending_call {
	dbus_pending_call_t *	next;
	uint32_t		seq;

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

struct dbus_service_proxy {
	dbus_service_proxy_t *	next;
	char *			bus_address;

	char *			name;
	dbus_client_t *		dbus;
};

struct dbus_bridge_port {
	char *			name;
	char *			bus_address;

	bool			open_for_business;

	dbus_timer_t *		reconnect_timer;
	dbus_client_t *		dbus;
	dbus_client_t *		monitor;

	dbus_bridge_port_t *	other;

	/* On the upstream port, this is a list of names that
	 * we want to create proxies for */
	struct strutil_array	names_to_publish;

	/* On the downstream port, this is the list of proxies
	 * we actually have active. */
	dbus_service_proxy_t *	service_proxies;
};

#ifdef ENABLE_MESSAGE_TRACING
# define trace_message		log_debug
# define trace_message_ep	endpoint_debug
#else
# define trace_message(fmt ...) do { } while (0)
# define trace_message_ep(ep, fmt...) do { } while (0)
#endif

static void		dbus_client_startup(dbus_client_t *dbus);
static void		dbus_message_free(dbus_message_t *msg);
static void		dbus_sigrec_free(dbus_sigrec_t *sig);

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

static inline dbus_sigrec_t *
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

static inline bool
dbus_signal_handler_match(const dbus_sigrec_t *sig, const dbus_message_t *msg)
{
	if (msg->interface_name == NULL || msg->member_name == NULL)
		return false;

	if (sig->interface && strcmp(sig->interface, msg->interface_name))
		return false;

	if (sig->member && strcmp(sig->member, msg->member_name))
		return false;

	return true;
}

static dbus_pending_call_t *
dbus_pending_call_new(uint32_t seq, dbus_response_handler_t handler)
{
	dbus_pending_call_t *call;

	call = calloc(1, sizeof(*call));
	call->seq = seq;
	call->handler = handler;
	return call;
}

static void
dbus_pending_call_free(dbus_pending_call_t *call)
{
	if (call->msg)
		dbus_message_free(call->msg);
	if (call->timer) {
		owl_timer_set_callback(call->timer, NULL, NULL);
		owl_timer_cancel(call->timer);
		owl_timer_release(call->timer);
		call->timer = NULL;
	}

	free(call);
}

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
		if (call->seq == seq) {
			*pos = call->next;
			call->next = NULL;
			break;
		}
	}

	return call;
}

static void
dbus_client_handle_timeouts(dbus_client_t *dbus)
{
	dbus_pending_call_t **pos, *call;

	log_debug("%s()", __func__);
	for (pos = &dbus->pending; (call = *pos) != NULL;) {
		dbus_debug(dbus, "call seq %u timeout %u", call->seq, call->timed_out);
		if (call->timed_out) {
			*pos = call->next;

			dbus_debug(dbus, "call (seq %u) timed out", call->seq);
			dbus_pending_call_free(call);
			continue;
		}

		pos = &call->next;
	}
}

static void
dbus_pending_call_timeout(owl_timer_t *timer, void *user_data)
{
	dbus_pending_call_t *call = user_data;

	log_debug("%s(%u)", __func__, call->seq);
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

static int
dbus_client_handle_signal(sd_bus_message *m, void *ptr, sd_bus_error *ret_error)
{
	dbus_client_t *dbus = ptr;
	dbus_sigrec_t *sig;

	for (sig = dbus->signal_handlers; sig; sig = sig->next) {
		if (sd_bus_message_is_signal(m, sig->interface, sig->member)) {
			// dbus_debug(dbus, "Processing signal %s.%s", sig->interface, sig->member);
			sig->handler(dbus, m);
		}
	}
	return 0;
}

static void
dbus_client_install_signal_handler(dbus_client_t *dbus,
		const char *interface, const char *member,
		dbus_signal_handler_t handler)
{
	dbus_sigrec_t *rec;
	int r;

	if (handler == NULL)
		return;

	rec = dbus_sigrec_new(interface, member, handler);
	rec->next = dbus->signal_handlers;
	dbus->signal_handlers = rec;

	r = sd_bus_match_signal(dbus->h, NULL,
			NULL,			/* sender */
			NULL,			/* object path */
			interface,
			member,
			dbus_client_handle_signal,
			dbus);

	if (r > 0)
		dbus_debug(dbus, "installed signal handler for %s.%s", interface, member);
}

static void
dbus_process_message(dbus_client_t *dbus, const dbus_message_t *msg)
{
	dbus_pending_call_t *call;

	if (msg->msg_type == DBUS_MSG_TYPE_METHOD_RETURN) {
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
	if (msg->msg_type == DBUS_MSG_TYPE_SIGNAL) {
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

static inline void
__dbus_message_make_header(dbus_client_t *dbus, uint8_t *header, uint8_t msg_type, uint8_t msg_flags, uint32_t msg_seq)
{
	uint32_t *words;

	header[0] = dbus->endianness;
	header[1] = msg_type;
	header[2] = msg_flags;
	header[3] = 1;

	words = (uint32_t *) (header + 4);
	words[0] = 0;
	words[1] = msg_seq;
}


static dbus_message_t *
dbus_message_new(dbus_client_t *dbus)
{
	dbus_message_t *msg;

	msg = calloc(1, sizeof(*msg));
	return msg;
}

static dbus_message_t *
dbus_message_builder_new(dbus_client_t *dbus, uint8_t msg_type, unsigned int msg_flags)
{
	dbus_message_t *msg;
	uint8_t fixed_header[12];

	msg = calloc(1, sizeof(*msg));
	msg->buffer = buffer_alloc_write(8192);
	msg->msg_seq = dbus->seq++;
	msg->msg_type = msg_type;

	/* Construct the fixed size header */
	__dbus_message_make_header(dbus, fixed_header, msg_type, msg_flags, msg->msg_seq);
	buffer_put(msg->buffer, fixed_header, sizeof(fixed_header));

	return msg;
}

static inline buffer_t *
dbus_message_build_payload(dbus_message_t *msg, size_t size_hint)
{
	if (msg->msg_payload == NULL)
		msg->msg_payload = buffer_alloc_write(size_hint? : 1024);
	return msg->msg_payload;
}

static void
dbus_message_free(dbus_message_t *msg)
{
	if (msg->buffer) {
		buffer_free(msg->buffer);
		msg->buffer = NULL;
	}

	if (msg->msg_payload) {
		buffer_free(msg->msg_payload);
		msg->msg_payload = NULL;
	}

	strutil_drop(&msg->sender);
	strutil_drop(&msg->destination);
	strutil_drop(&msg->object_path);
	strutil_drop(&msg->interface_name);
	strutil_drop(&msg->member_name);
	strutil_drop(&msg->error_name);
	strutil_drop(&msg->signature);

	free(msg);
}

static const char *
dbus_message_type_to_string(unsigned int type)
{
	static const char *	names[__DBUS_MSG_TYPE_MAX] = {
		[DBUS_MSG_TYPE_METHOD_CALL] = "call",
		[DBUS_MSG_TYPE_METHOD_RETURN] = "response",
		[DBUS_MSG_TYPE_ERROR] = "error",
		[DBUS_MSG_TYPE_SIGNAL] = "signal",
	};
	const char *name = NULL;

	if (type < __DBUS_MSG_TYPE_MAX)
		name = names[type];
	if (name == NULL)
		return "unknown";
	return name;
}

static inline void
dbus_message_display(const endpoint_t *ep, const char *verb, const dbus_message_t *msg)
{
	struct strutil_dynstr ds = STRUTIL_DYNSTR_INIT;

	if (msg->sender)
		strutil_dynstr_appendf(&ds, "; sender=%s", msg->sender);
	if (msg->destination)
		strutil_dynstr_appendf(&ds, "; destination=%s", msg->destination);
	if (msg->object_path)
		strutil_dynstr_appendf(&ds, "; path=%s", msg->object_path);
	if (msg->interface_name)
		strutil_dynstr_appendf(&ds, "; interface=%s", msg->interface_name);
	if (msg->member_name)
		strutil_dynstr_appendf(&ds, "; member=%s", msg->member_name);
	if (msg->error_name)
		strutil_dynstr_appendf(&ds, "; error=%s", msg->error_name);
	if (msg->reply_serial)
		strutil_dynstr_appendf(&ds, "; reply-serial=%u", msg->reply_serial);

	endpoint_debug(ep,
			"%s %s%s", verb, dbus_message_type_to_string(msg->msg_type),
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
__dbus_message_put_byte(buffer_t *bp, uint8_t byte)
{
	return buffer_put(bp, &byte, 1);
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

static bool
__dbus_message_get_string_header(buffer_t *bp, char field_type, char **var)
{
	char signature[2] = { field_type, 0 };

	if (!__dbus_message_check_signature(bp, signature))
		return false;

	return __dbus_message_get_string(bp, var);
}

static bool
__dbus_message_get_uint32(buffer_t *bp, uint32_t *var)
{
	if (!__dbus_message_check_signature(bp, "u"))
		return false;

	if (!buffer_consume_padding(bp, 4))
		return false;

	return buffer_get(bp, var, 4);
}

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

dbus_message_t *
dbus_message_method_call(dbus_client_t *dbus, const char *destination, const char *object_path, const char *interface_name, const char *member_name, const char *signature)
{
	dbus_message_t *msg;

	msg = dbus_message_builder_new(dbus, DBUS_MSG_TYPE_METHOD_CALL, 0);
	strutil_set(&msg->sender, dbus->bus_name);

	strutil_set(&msg->destination, destination);
	strutil_set(&msg->object_path, object_path);
	strutil_set(&msg->interface_name, interface_name);
	strutil_set(&msg->member_name, member_name);
	strutil_set(&msg->signature, signature);

	return msg;
}

bool
dbus_message_method_build_header(dbus_message_t *msg)
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

	if (!__dbus_message_header_put_object_path(bp, DBUS_HDR_FIELD_PATH, msg->object_path)
	 || !__dbus_message_header_put_string(bp, DBUS_HDR_FIELD_DESTINATION, msg->destination)
	 || !__dbus_message_header_put_string(bp, DBUS_HDR_FIELD_INTERFACE, msg->interface_name)
	 || !__dbus_message_header_put_string(bp, DBUS_HDR_FIELD_MEMBER, msg->member_name)
	 || !__dbus_message_header_put_signature(bp, DBUS_HDR_FIELD_SIGNATURE, msg->signature)
	 )
		return false;

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
dbus_message_transmit(endpoint_t *ep, queue_t *q, dbus_message_t *msg)
{
	buffer_t *bp;

	dbus_message_display(ep, "sending", msg);

	if (!dbus_message_method_build_header(msg))
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
dbus_message_parse_header(buffer_t *hdr, dbus_message_t *msg)
{
	unsigned char fixed_header[12 + 4];	/* fixed header + header field array length */

	if (!buffer_get(hdr, fixed_header, sizeof(fixed_header)))
		return false;

	msg->msg_type = fixed_header[1];
	msg->msg_flags = fixed_header[2];
	msg->msg_seq = *(uint32_t *) (fixed_header + 8);

	while (buffer_available(hdr)) {
		uint8_t field_type;

		// __dbus_message_display_next(hdr);

		if (!buffer_consume_padding(hdr, 8))
			return false;

		buffer_get_u8(hdr, &field_type);

		switch (field_type) {
		case DBUS_HDR_FIELD_PATH:
			if (!__dbus_message_get_string_header(hdr, 'o', &msg->object_path))
				return false;
			trace_message(" object_path %s", msg->object_path);
			break;

		case DBUS_HDR_FIELD_INTERFACE:
			if (!__dbus_message_get_string_header(hdr, 's', &msg->interface_name))
				return false;
			trace_message(" interface %s", msg->interface_name);
			break;

		case DBUS_HDR_FIELD_MEMBER:
			if (!__dbus_message_get_string_header(hdr, 's', &msg->member_name))
				return false;
			trace_message(" member %s", msg->member_name);
			break;

		case DBUS_HDR_FIELD_ERROR_NAME:
			if (!__dbus_message_get_string_header(hdr, 's', &msg->error_name))
				return false;
			trace_message(" error %s", msg->error_name);
			break;

		case DBUS_HDR_FIELD_SIGNATURE:
			if (!__dbus_message_get_signature(hdr, &msg->signature))
				return false;
			trace_message(" signature %s", msg->signature);
			break;

		case DBUS_HDR_FIELD_REPLY_SERIAL:
			if (!__dbus_message_get_uint32(hdr, &msg->reply_serial))
				return false;
			trace_message(" reply_serial %u", msg->reply_serial);
			break;

		case DBUS_HDR_FIELD_DESTINATION:
			if (!__dbus_message_get_string_header(hdr, 's', &msg->destination))
				return false;
			trace_message(" dest %s", msg->destination);
			break;

		case DBUS_HDR_FIELD_SENDER:
			if (!__dbus_message_get_string_header(hdr, 's', &msg->sender))
				return false;
			trace_message(" sender %s", msg->sender);
			break;

		default:
			trace_message("unsupported header field %u", field_type);
			return false;
		}
	}

	return true;
}

static dbus_message_t *
dbus_message_dissect(dbus_client_t *dbus, endpoint_t *ep, queue_t *q)
{
	unsigned char fixed_header[12 + 4];	/* fixed header + header field array length */
	uint32_t msg_seq, payload_len, header_len, payload_alignment, total_msg_size;
	dbus_message_t *msg;
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

	msg = dbus_message_new(dbus);
	if (!dbus_message_parse_header(hdr, msg)) {
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
		dbus_message_free(msg);
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

static inline bool
dbus_message_verify_signature(dbus_client_t *dbus, const dbus_message_t *msg, const char *expected_signature)
{
	if (!msg->signature || strcmp(msg->signature, expected_signature)) {
		endpoint_error(dbus->ep, "invalid signature \"%s\" in response", msg->signature);
		return false;
	}

	return true;
}

#if 0
static bool
dbus_maybe_process_error_response(dbus_client_t *dbus, sd_bus_message *m, sd_bus_error *_err)
{
	const sd_bus_error *err;

	if (sd_bus_message_is_method_error(m, NULL) <= 0)
		return false;

	err = sd_bus_message_get_error(m);
	dbus_debug(dbus, "Error: %s: %s", err->name, err->message);

	/* XXX should free? */
	return true;
}

static bool
dbus_message_get_string_array(sd_bus_message *m, struct strutil_array *result)
{
	char **decoded = NULL;
	unsigned int i;

	strutil_array_destroy(result);
	if (sd_bus_message_verify_type(m, 'a', "s") < 0) {
		log_error("Cannot process message, expected array of strings");
		return false;
	}

	if (sd_bus_message_read_strv(m, &decoded) < 0) {
		log_error("Failed to decode string array");
		return false;
	}

	for (i = 0; decoded[i]; ++i)
		;

	result->count = i;
	result->data = decoded;
	return true;
}


static int
dbus_process_hello_response(struct sd_bus_message *m, void *ptr, sd_bus_error *err)
{
	dbus_client_t *dbus = (dbus_client_t *) ptr;
	char *name = NULL;
	int r;

	dbus_debug(dbus, "Processing Hello response");

	if (dbus_maybe_process_error_response(dbus, m, err))
		return -1;

	if ((r = sd_bus_message_read(m, "s", &name)) < 0)
		return r;
	dbus_debug(dbus, "assigned DBus name is \"%s\"", name);
	return 0;
#if 0
	if (!dbus_message_verify_signature(dbus, msg, "s"))
 		return -1;

	if (!__dbus_message_get_string(msg->msg_payload, &name))
		return -1;

	dbus_debug(dbus, "assigned DBus name is \"%s\"", name);
	strutil_drop(&dbus->bus_name);
	dbus->bus_name = name;
	return 0;
#endif
}

static void
dbus_queue_hello(dbus_client_t *dbus, endpoint_t *ep, queue_t *q)
{
	sd_bus_message *m;

	sd_bus_message_new_method_call(dbus->h, &m,
			"org.freedesktop.DBus",		/* destination */
			"/org/freedesktop/DBus",	/* object path */
			"org.freedesktop.DBus",		/* interface */
			"Hello");			/* member */

	sd_bus_call_async(dbus->h, NULL, m, dbus_process_hello_response, dbus, 0);
}

static int
dbus_process_list_names_response(struct sd_bus_message *m, void *ptr, sd_bus_error *err)
{
	dbus_client_t *dbus = (dbus_client_t *) ptr;
	struct strutil_array names = { 0 };

	dbus_debug(dbus, "Processing ListNames response");

	if (dbus_maybe_process_error_response(dbus, m, err))
		return -1;

	if (!dbus_message_get_string_array(m, &names))
		return -1;

	dbus_debug(dbus, "received %u names", names.count);
	if (dbus->impl.ops->process_registered_names)
		dbus->impl.ops->process_registered_names(dbus, (const char **) names.data, names.count);

	strutil_array_destroy(&names);
	dbus_client_startup(dbus);
	return 0;
}

static void
dbus_queue_list_names(dbus_client_t *dbus, endpoint_t *ep, queue_t *q)
{
	sd_bus_message *m;

	sd_bus_message_new_method_call(dbus->h, &m,
			"org.freedesktop.DBus",		/* destination */
			"/org/freedesktop/DBus",	/* object path */
			"org.freedesktop.DBus",		/* interface */
			"ListNames");			/* member */

	sd_bus_call_async(dbus->h, NULL, m, dbus_process_list_names_response, dbus, 0);
}

static sd_bus_message *
dbus_list_names_build_call(dbus_client_t *dbus)
{
	sd_bus_message *m;

	sd_bus_message_new_method_call(dbus->h, &m,
			"org.freedesktop.DBus",		/* destination */
			"/org/freedesktop/DBus",	/* object path */
			"org.freedesktop.DBus",		/* interface */
			"ListNames");			/* member */

	return m;
}

static bool
dbus_list_names_response(dbus_client_t *dbus, sd_bus_message *m)
{
	struct strutil_array names = { 0 };

	dbus_debug(dbus, "Processing ListNames response");
	if (!dbus_message_get_string_array(m, &names))
		return false;

	dbus_debug(dbus, "received %u names", names.count);
	if (dbus->impl.ops->process_registered_names)
		dbus->impl.ops->process_registered_names(dbus, (const char **) names.data, names.count);

	strutil_array_destroy(&names);
	dbus_client_startup(dbus);
	return true;
}

static dbus_call_t	list_names_call = {
	.build_call	= dbus_list_names_build_call,
	.response	= dbus_list_names_response,
};
#endif

/*
 * AddMatch
 */
static int
dbus_process_become_monitor_response(struct sd_bus_message *m, void *ptr, sd_bus_error *err)
{
	dbus_client_t *dbus = (dbus_client_t *) ptr;

	dbus_debug(dbus, "Received BecomeMonitor response");
	return 0;
}

static inline void
dbus_queue_become_monitor(dbus_client_t *dbus, endpoint_t *ep, queue_t *q)
{
	sd_bus_message *m;
	const char *matches[16];
	unsigned int nmatches = 0;
	uint32_t flags = 0;

	if (dbus->impl.ops->name_owner_changed)
		matches[nmatches++] = "type=signal,interface=org.freedesktop.DBus,member=NameOwnerChanged,eavesdrop=true";
	if (dbus->impl.ops->name_acquired)
		matches[nmatches++] = "type=signal,interface=org.freedesktop.DBus,member=NameAcquired,eavesdrop=true";
	if (dbus->impl.ops->name_lost)
		matches[nmatches++] = "type=signal,interface=org.freedesktop.DBus,member=NameLost,eavesdrop=true";
	matches[nmatches] = NULL;

	sd_bus_message_new_method_call(dbus->h, &m,
			"org.freedesktop.DBus",		/* destination */
			"/org/freedesktop/DBus",	/* object path */
			"org.freedesktop.DBus.Monitoring", /* interface */
			"BecomeMonitor");		/* member */

	if (sd_bus_message_append_strv(m, (char **) matches) < 0
	 || sd_bus_message_append_basic(m, SD_BUS_TYPE_UINT32, &flags) < 0)
		return;

	sd_bus_call_async(dbus->h, NULL, m, dbus_process_become_monitor_response, dbus, 0);
}

/*
 * RequestName
 */
#if 0
static int
dbus_process_request_name_response(struct sd_bus_message *m, void *ptr, sd_bus_error *err)
{
	dbus_client_t *dbus = (dbus_client_t *) ptr;

	dbus_debug(dbus, "Received RequestName response");

	if (dbus_maybe_process_error_response(dbus, m, err))
		return -1;

	return 0;
}

static void
dbus_queue_request_name(dbus_client_t *dbus, endpoint_t *ep, queue_t *q)
{
	sd_bus_message *m;
	uint32_t flags = 0;

	if (!dbus->request_name)
		return;

	dbus_debug(dbus, "RequestName(%s)", dbus->request_name);
	sd_bus_message_new_method_call(dbus->h, &m,
			"org.freedesktop.DBus",		/* destination */
			"/org/freedesktop/DBus",	/* object path */
			"org.freedesktop.DBus",		/* interface */
			"RequestName");			/* member */

	if (sd_bus_message_append(m, "su", dbus->request_name, flags) < 0)
		return;

	sd_bus_call_async(dbus->h, NULL, m, dbus_process_request_name_response, dbus, 0);
}
#endif

static void
dbus_client_handle_name_acquired_signal(dbus_client_t *dbus, sd_bus_message *m)
{
	const char *name = NULL;

	if (sd_bus_message_read(m, "s", &name) <= 0)
		return;

	dbus_debug(dbus, "NameAcquired: %s", name);
	if (dbus->impl.ops->name_acquired)
		dbus->impl.ops->name_acquired(dbus, name);
}

static void
dbus_client_handle_name_lost_signal(dbus_client_t *dbus, sd_bus_message *m)
{
	const char *name = NULL;

	if (sd_bus_message_read(m, "s", &name) <= 0)
		return;

	if (dbus->impl.ops->name_lost)
		dbus->impl.ops->name_lost(dbus, name);
}

static void
dbus_client_handle_name_owner_changed_signal(dbus_client_t *dbus, sd_bus_message *m)
{
	const char *name = NULL, *old_owner = NULL, *new_owner = NULL;

	if (sd_bus_message_read(m, "sss", &name, &old_owner, &new_owner) <= 0)
		return;

	/* Ignore all owner changes for :x.y bus names */
	if (name[0] == ':')
		return;

	dbus_debug(dbus, "NameOwnerChanged(%s, %s, %s)", name, old_owner, new_owner);
	if (dbus->impl.ops->name_owner_changed)
		dbus->impl.ops->name_owner_changed(dbus, name, old_owner, new_owner);
}

static void
dbus_client_get_data(endpoint_t *ep, queue_t *q, struct sender *s)
{
	dbus_client_t *dbus = s->handle;

	dbus_debug(dbus, "%s(), state=%u", __func__, dbus->state);
	dbus_client_handle_timeouts(dbus);

	if (dbus->state == STATE_SEND_AUTH) {
		dbus->state = STATE_AWAIT_AUTH_RESPONSE;
	} else
	if (dbus->state == STATE_STARTUP_SENDING) {
		dbus_client_ops_t *ops = dbus->impl.ops;
		struct dbus_startup_call *next_step = NULL;

		if (ops && ops->startup_sequence)
			next_step = &ops->startup_sequence[dbus->startup_step];

		if (next_step && next_step->name) {
			dbus_debug(dbus, "Performing step %u of startup sequence: %s", dbus->startup_step, next_step->name);
			next_step->queue_fn(dbus, ep, q);
			dbus->state = STATE_STARTUP_AWAIT_RESPONSE;
			dbus->startup_step += 1;
		} else {
			dbus->state = STATE_RELAYING;
		}
	} else
	if (dbus->state == STATE_RELAYING) {
		/* TBD */
	} else
	if (dbus->state == STATE_SHUTTING_DOWN) {
		/* We tell dbus-daemon that we're done. It will flush its
		 * buffers and the close its connection. At that point,
		 * we will see EOF from our peer, and will close the
		 * endpoint for real. */
		endpoint_shutdown_write(ep);
	}
}

struct sender *
dbus_client_sender(void *handle)
{
	struct sender *s;

	s = calloc(1, sizeof(*s));
	s->handle = handle;
	s->get_data = dbus_client_get_data;

	return s;
}

static bool
dbus_client_push_data(endpoint_t *ep, queue_t *q, struct receiver *r)
{
	dbus_client_t *dbus = r->handle;
	dbus_message_t *msg;

	assert(q);
	assert(q == r->recvq);

	/* If there's no data in the queue, then we can rightfully claim we were
	 * able to process it in its entirety. */
	if (q->size == 0)
		return false;

	while (q->size) {
		/* dissect message and process it */
		msg = dbus_message_dissect(dbus, ep, q);
		if (msg == NULL)
			return false;

		dbus_message_display(ep, "received", msg);
		dbus_process_message(dbus, msg);

		trace_message_ep("====");
		dbus_message_free(msg);
	}

	/* return true if there's unprocessed data */
	trace_message_ep(ep, "amount of data left: %u", q->size);
	return false;
}

struct receiver *
dbus_client_receiver(void *handle)
{
	struct receiver *r;

	r = calloc(1, sizeof(*r));
	r->handle = handle;
	r->push_data = dbus_client_push_data;
	r->recvq = &r->__queue;

	return r;
}

/*
 * authentication stage
 */
static bool
dbus_auth_send_line(endpoint_t *ep, queue_t *q, const char *fmt, ...)
{
	char linebuf[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(linebuf, sizeof(linebuf), fmt, ap);
	va_end(ap);

	return queue_append(q, linebuf, strlen(linebuf));
}

/* 100 is encoded as 313030 */
static const char *
funky_uid_encoding(uid_t uid)
{
	static char uidbuf[16];
	char *t;

	if (uid == 0)
		return "30";

	memset(uidbuf, 0, sizeof(uidbuf));

	t = uidbuf + sizeof(uidbuf);
	while (uid) {
		if (t <= uidbuf + 2)
			return NULL;
		*--t = '0' + (uid % 10);
		*--t = '3';

		uid /= 10;
	}
	return t;
}

static bool
dbus_auth_send_auth_external(endpoint_t *ep, queue_t *q)
{
	const char *encoded_uid;

	if (!(encoded_uid = funky_uid_encoding(getuid())))
		return false;

	return dbus_auth_send_line(ep, q, "AUTH EXTERNAL %s\r\n", encoded_uid);
}

static void
dbus_auth_get_data(endpoint_t *ep, queue_t *q, struct sender *s)
{
	dbus_client_t *dbus = s->handle;

	if (dbus->state == STATE_SEND_AUTH) {
		/* Send a single NUL byte for credentials passing */
		queue_append(q, "\0", 1);

		dbus_auth_send_auth_external(ep, q);
		dbus->state = STATE_AWAIT_AUTH_RESPONSE;
	} else
	if (dbus->state == STATE_SEND_BEGIN) {
		dbus_auth_send_line(ep, q, "BEGIN\r\n");
		endpoint_set_upper_layer(ep, dbus_client_sender(dbus), dbus_client_receiver(dbus));

		if (dbus->impl.ops && dbus->impl.ops->startup_sequence) {
			dbus->state = STATE_STARTUP_SENDING;
		} else {
			dbus->state = STATE_RELAYING;
		}
	}
}

struct sender *
dbus_auth_sender(void *handle)
{
	struct sender *s;

	s = calloc(1, sizeof(*s));
	s->handle = handle;
	s->get_data = dbus_auth_get_data;

	return s;
}

static bool
dbus_auth_push_data(endpoint_t *ep, queue_t *q, struct receiver *r)
{
	dbus_client_t *dbus = r->handle;
	char linebuf[512];

	assert(q);
	assert(q == r->recvq);

	while (queue_gets(q, linebuf, sizeof(linebuf))) {
		linebuf[strcspn(linebuf, "\r\n")] = '\0';
		dbus_debug(dbus, "received <%s>", linebuf);

		if (dbus->state == STATE_AWAIT_AUTH_RESPONSE) {
			if (strncmp(linebuf, "OK", 2)) {
				endpoint_error(ep, "authentication failed (%s)", linebuf);
				log_fatal("Unable to proceed");
			}

			dbus_debug(dbus, "authentication okay");
			dbus->state = STATE_SEND_BEGIN;
		}
	}
	return false;
}

struct receiver *
dbus_auth_receiver(void *handle)
{
	struct receiver *r;

	r = calloc(1, sizeof(*r));
	r->handle = handle;
	r->push_data = dbus_auth_push_data;
	r->recvq = &r->__queue;

	return r;
}

static inline endpoint_t *
dbus_create_endpoint(dbus_client_t *dbus, const char *dbus_path)
{
	endpoint_t *ep;

	ep = endpoint_create_unix_client(dbus_path);

	if (0)
		endpoint_set_debug(ep, dbus->debug_name, -1);

	endpoint_set_upper_layer(ep, dbus_auth_sender(dbus), dbus_auth_receiver(dbus));
//	endpoint_register_close_callback(ep, dbus_client_close_callback, dbus);
	io_register_endpoint(ep);

	return ep;
}

void
dbus_client_startup(dbus_client_t *dbus)
{
	dbus_client_ops_t *ops = dbus->impl.ops;
	struct dbus_startup_call *next_step = NULL;

	if (ops && ops->startup_sequence)
		next_step = &ops->startup_sequence[dbus->startup_step];

	if (next_step && next_step->name) {
		dbus_debug(dbus, "Performing step %u of startup sequence: %s", dbus->startup_step, next_step->name);
		next_step->queue_fn(dbus, NULL, NULL);
		dbus->state = STATE_STARTUP_AWAIT_RESPONSE;
		dbus->startup_step += 1;
	}
}

void
dbus_client_disconnect(dbus_client_t *dbus)
{
	if (dbus->h == NULL)
		return;

	dbus_debug(dbus, "disconnecting");
	sd_bus_unref(dbus->h);
	dbus->h = NULL;
}

static int
dbus_client_hangup_callback(sd_event_source *s, int fd, uint32_t revents, void *userdata)
{
	dbus_client_t *dbus = userdata;

	dbus_debug(dbus, "%s()", __func__);
	if (!(revents & POLLHUP))
		return 0;

	dbus_debug(dbus, "connection closed by peer");
	dbus_client_disconnect(dbus);
	sd_event_source_unref(s);
	close(fd);

	if (dbus->impl.ops->connection_lost)
		dbus->impl.ops->connection_lost(dbus);

	return 0;
}

bool
dbus_client_connect(dbus_client_t *dbus, const char *dbus_path)
{
	sd_event *event;
	int r;

	if (dbus->h != NULL) {
		log_error_id(dbus->debug_name, "already connected");
		return false;
	}

	if (dbus_path == NULL) {
		unsetenv("DBUS_SYSTEM_BUS_ADDRESS");
	} else {
		char addrstring[256];

		snprintf(addrstring, sizeof(addrstring), "unix:path=%s", dbus_path);
		setenv("DBUS_SYSTEM_BUS_ADDRESS", addrstring, 1);
	}

	if ((r = sd_bus_open_system_with_description(&dbus->h, dbus->debug_name)) < 0) {
		dbus_debug(dbus, "sd_bus_open failed: %s", strerror(-r));
		return false;
	}

	if (sd_event_default(&event) < 0)
		log_fatal("Unable to create sd-event loop");
	sd_bus_attach_event(dbus->h, event, SD_EVENT_PRIORITY_NORMAL);

	{
		int fd;

		if ((fd = sd_bus_get_fd(dbus->h)) < 0)
			log_fatal("unable to get fd of dbus client");

		/* We cannot install two event handlers for the same fd. Thus, dup()
		 * the fd and make sure dbus_client_hangup_callback() closes it */
		fd = dup(fd);

		sd_event_add_io(event, NULL, fd, EPOLLHUP, dbus_client_hangup_callback, dbus);
	}

	{
		const char *sender = NULL;

		if (sd_bus_get_unique_name(dbus->h, &sender) == 0)
			strutil_set(&dbus->bus_name, sender);
	}

	dbus_debug(dbus, "connected to DBus broker; my bus name %s", dbus->bus_name);

	if (dbus->impl.ops->name_acquired)
		dbus_client_install_signal_handler(dbus, 
			"org.freedesktop.DBus", "NameAcquired",
			dbus_client_handle_name_acquired_signal);

	if (dbus->impl.ops->name_lost)
		dbus_client_install_signal_handler(dbus, 
			"org.freedesktop.DBus", "NameLost",
			dbus_client_handle_name_lost_signal);

	if (dbus->impl.ops->name_owner_changed)
		dbus_client_install_signal_handler(dbus, 
			"org.freedesktop.DBus", "NameOwnerChanged",
			dbus_client_handle_name_owner_changed_signal);

	dbus_client_startup(dbus);
	return true;
}

/*
 * Timers
 */
static int
__dbus_timer_callback(sd_event_source *s, uint64_t usec, void *userdata)
{
	static const unsigned long max_backoff = 30000000; /* 30 seconds */
	dbus_timer_t *timer = userdata;

	if (!timer->callback(timer->userdata)) {
		sd_event_source_set_enabled(timer->event_source, SD_EVENT_OFF);
		return 0;
	}

	if (timer->current_timeout_ms == 0) {
		timer->current_timeout_ms = timer->initial_timeout_ms;
	} else {
		timer->current_timeout_ms <<= 1;
		if (timer->current_timeout_ms > max_backoff)
			timer->current_timeout_ms = max_backoff;
	}

	/* Come back after the specified timeout */
	sd_event_source_set_time_relative(timer->event_source, timer->current_timeout_ms);
	return 1;
}


static dbus_timer_t *
dbus_timer_new(unsigned long timeout_ms, dbus_timer_callback_fn_t *callback, void *userdata)
{
	dbus_timer_t *timer;
	sd_event *event;

	timer = calloc(1, sizeof(*timer));
	timer->initial_timeout_ms = timeout_ms;
	timer->callback = callback;
	timer->userdata = userdata;

	if (sd_event_default(&event) < 0)
		log_fatal("sd_event_default failed");

	sd_event_add_time_relative(event, &timer->event_source, CLOCK_MONOTONIC, 0, timeout_ms / 10, __dbus_timer_callback, timer);
	sd_event_source_set_enabled(timer->event_source, SD_EVENT_ON);
	return timer;
}

static void
dbus_timer_restart(dbus_timer_t *timer)
{
	assert(timer->event_source);

	/* re-enable the timer and ensure it fires immediately */
	sd_event_source_set_enabled(timer->event_source, SD_EVENT_ON);
	sd_event_source_set_time_relative(timer->event_source, 0);
	timer->current_timeout_ms = 0;
}

/*
 * Create a timer connected to a bridge port
 */
static void
dbus_bridge_add_timer(dbus_bridge_port_t *port, unsigned long timeout_ms, int (*callback)(dbus_bridge_port_t *))
{
	if (port->reconnect_timer == NULL)
		port->reconnect_timer = dbus_timer_new(timeout_ms, (dbus_timer_callback_fn_t *) callback, port);
	else
		dbus_timer_restart(port->reconnect_timer);
}

/*
 * Implementation of the bridge port
 */
static struct dbus_startup_call	dbus_bridge_startup_sequence[] = {
//	{ "Hello",		dbus_queue_hello	},
//	{ "ListNames",		dbus_queue_list_names	},

	{ NULL, }
};

static void
dbus_bridge_name_acquired(dbus_client_t *dbus, const char *name)
{
	dbus_debug(dbus, "acquired name", name);
}

static void
dbus_bridge_name_lost(dbus_client_t *dbus, const char *name)
{
	dbus_debug(dbus, "lost name", name);
}

static void
dbus_bridge_process_registered_names(dbus_client_t *dbus, const char **names, unsigned int count)
{
	dbus_bridge_port_t *port = dbus->impl.data;

	if (port == NULL || port->names_to_publish.count == 0)
		return;

	while (count--) {
		const char *name = *names++;

		if (name[0] == ':')
			continue;

		dbus_debug(dbus, "  %s", name);
		dbus_bridge_port_event_name_acquired(port, name);
	}
}

static dbus_client_ops_t	dbus_impl_bridge = {
	.startup_sequence = dbus_bridge_startup_sequence,
	.process_registered_names = dbus_bridge_process_registered_names,
	.name_acquired = dbus_bridge_name_acquired,
	.name_lost = dbus_bridge_name_lost,
};

/*
 * Implementation of the monitor
 */
static struct dbus_startup_call	dbus_monitor_startup_sequence[] = {
//	{ "Hello",		dbus_queue_hello	},
//	{ "ListNames",		dbus_queue_list_names	},
//	{ "BecomeMonitor",	dbus_queue_become_monitor },

	{ NULL }
};

static int
__dbus_monitor_reconnect(dbus_bridge_port_t *port)
{
	dbus_client_t *dbus = port->monitor;
	dbus_service_proxy_t *proxy;

	dbus_debug(dbus, "Trying to reconnect");
	if (dbus->h == NULL && !dbus_client_connect(dbus, port->bus_address)) {
		return 1;
	}

	dbus_debug(dbus, "Connected, opening up for business");
	port->open_for_business = true;

	/* Loop over all proxies and reconnect those as well. */
	for (proxy = port->service_proxies; proxy; proxy = proxy->next) {
		if (proxy->dbus && !proxy->dbus->h)
			dbus_service_proxy_connect(proxy, port);
	}

	return 0;
}

static void
dbus_monitor_attempt_reconnect(dbus_bridge_port_t *port)
{
	dbus_client_t *dbus = port->monitor;

	if (dbus->h) {
		dbus_debug(dbus, "%s: already connected", __func__);
		return;
	}

	dbus_bridge_add_timer(port, 1000000, __dbus_monitor_reconnect);
}


static void
dbus_monitor_connection_lost(dbus_client_t *dbus)
{
	dbus_bridge_port_t *port = dbus->impl.data;
	dbus_service_proxy_t *proxy;

	/* can this happen? */
	if (dbus != port->monitor)
		return;

	dbus_debug(dbus, "lost connection to DBus broker");
	port->open_for_business = false;

	for (proxy = port->service_proxies; proxy; proxy = proxy->next) {
		if (proxy->dbus)
			dbus_client_disconnect(proxy->dbus);
	}

	dbus_monitor_attempt_reconnect(port);
}

static void
dbus_monitor_name_owner_changed(dbus_client_t *dbus, const char *name, const char *old_owner, const char *new_owner)
{
	dbus_bridge_port_t *port = dbus->impl.data;

	if (new_owner == NULL || *new_owner == '\0') {
		dbus_debug(dbus, "%s dropped", name);
		if (port)
			dbus_bridge_port_event_name_lost(port, name);
	} else {
		dbus_debug(dbus, "%s acquired by %s", name, new_owner);
		if (port)
			dbus_bridge_port_event_name_acquired(port, name);
	}
}

static dbus_client_ops_t	dbus_impl_monitor = {
	.startup_sequence = dbus_monitor_startup_sequence,
	.connection_lost = dbus_monitor_connection_lost,
	.name_owner_changed = dbus_monitor_name_owner_changed,
	.process_registered_names = dbus_bridge_process_registered_names,
};

/*
 * DBus methods for proxy
 */
static struct dbus_startup_call	dbus_proxy_startup_sequence[] = {
//	{ "Hello",		dbus_queue_hello	},
//	{ "RequestName",	dbus_queue_request_name },

	{ NULL }
};

static void
dbus_proxy_connection_lost(dbus_client_t *dbus)
{
	dbus_bridge_port_t *port = dbus->impl.data;
	dbus_service_proxy_t *proxy;

	for (proxy = port->service_proxies; proxy; proxy = proxy->next) {
		if (dbus == proxy->dbus) {
			log_debug_id(port->name, "proxy %s lost connection", proxy->name);
		}
	}
}

static int
__dbus_service_proxy_process_incoming(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
	dbus_service_proxy_t *proxy = userdata;
	uint8_t msg_type;

	log_debug("%s()", __func__);
	if (sd_bus_message_get_type(m, &msg_type) < 0)
		return 0;

	log_debug("  msg type=%u", msg_type);
	switch (msg_type) {
	case SD_BUS_MESSAGE_METHOD_CALL:
	case SD_BUS_MESSAGE_SIGNAL:
		break;

	case SD_BUS_MESSAGE_METHOD_RETURN:
	case SD_BUS_MESSAGE_METHOD_ERROR:
	default:
		return 0;
	}

	return 0;
}

static dbus_client_ops_t	dbus_impl_proxy = {
	.startup_sequence = dbus_proxy_startup_sequence,
	.connection_lost = dbus_proxy_connection_lost,
};

/*
 * Service proxy
 */
static dbus_service_proxy_t *
dbus_service_proxy_new(const char *name, const char *bus_address)
{
	dbus_service_proxy_t *proxy;

	proxy = calloc(1, sizeof(*proxy));
	strutil_set(&proxy->name, name);
	strutil_set(&proxy->bus_address, bus_address);
	return proxy;
}

static bool
dbus_service_proxy_connect(dbus_service_proxy_t *proxy, dbus_bridge_port_t *port)
{
	dbus_client_t *dbus;
	char name[128];
	int r;

	if (proxy->dbus && proxy->dbus->h) {
		dbus_debug(proxy->dbus, "already connected");
		return true;
	}

	if (port->bus_address == NULL) {
		log_error("%s: cannot create proxy %s: no bus address set", port->name, proxy->name);
		return false;
	}

	if (proxy->dbus == NULL) {
		/* Create the dbus client and connect, claiming the name we've been given */
		snprintf(name, sizeof(name), "%s:%s", port->name, proxy->name);
		dbus = dbus_client_new(name, &dbus_impl_proxy, port);
		proxy->dbus = dbus;

		strutil_set(&dbus->request_name, proxy->name);
	} else {
		dbus = proxy->dbus;
	}

	if (!port->open_for_business) {
		dbus_debug(dbus, "Defer connect() call until the downstream bus broker is running");
		return true;
	} else
	if (!dbus_client_connect(dbus, port->bus_address)) {
		log_error_id(dbus->debug_name, "Failed to connect to DBus");
		/* mark this proxy as failed */
		return false;
	}

	r = sd_bus_request_name(dbus->h, dbus->request_name, 0);
	if (r < 0) {
		log_error("Failed to acquire bus name %s on %s port: %s",
				dbus->request_name, port->name, strerror(-r));
		/* mark this proxy as failed */
		return false;
	}

	dbus_debug(dbus, "Acquired name %s", dbus->request_name);

	sd_bus_add_filter(dbus->h, NULL, __dbus_service_proxy_process_incoming, proxy);

	return true;
}

/*
 * Bridge port class
 */
dbus_bridge_port_t *
dbus_bridge_port_new(const char *name, const char *bus_address)
{
	dbus_bridge_port_t *port;

	port = calloc(1, sizeof(*port));
	strutil_set(&port->name, name);
	strutil_set(&port->bus_address, bus_address);
	return port;
}

void
dbus_bridge_port_publish(dbus_bridge_port_t *port, const char *name)
{
	strutil_array_append(&port->names_to_publish, name);
}

bool
dbus_bridge_port_monitor(dbus_bridge_port_t *port, bool deferred)
{
	char name[64];

	snprintf(name, sizeof(name), "%s-mon", port->name);
	log_debug("Creating port monitor for port %s", port->name);

	port->monitor = dbus_client_new(name, &dbus_impl_monitor, port);
	if (deferred) {
		dbus_monitor_attempt_reconnect(port);
	} else {
		if (!dbus_client_connect(port->monitor, port->bus_address)) {
			log_error("Unable to create dbus monitor\n");
			return false;
		}

		port->open_for_business = true;
	}

	return true;
}

bool
dbus_bridge_port_connect(dbus_bridge_port_t *port)
{
	char name[64];

	snprintf(name, sizeof(name), "%s-port", port->name);
	port->dbus = dbus_client_new(name, &dbus_impl_bridge, port);
	if (!dbus_client_connect(port->dbus, port->bus_address)) {
		log_error("Unable to create dbus bridge port\n");
		return false;
	}

	port->open_for_business = true;
	return true;
}

bool
dbus_bridge_port_list_names(dbus_bridge_port_t *port)
{
	dbus_client_t *dbus = port->monitor;
	char **registered = NULL;
	int r;

	if (!dbus || !dbus->h) {
		log_debug_id(port->name, "%s: not connected", __func__);
		return false;
	}

	r = sd_bus_list_names(dbus->h, &registered, NULL);
	if (r >= 0) {
		unsigned int count;

		for (count = 0; registered[count]; ++count)
			;

		dbus_debug(dbus, "Found %u registered names", count);
		dbus_bridge_process_registered_names(dbus, (const char **) registered, count);

		{
			char **p;

			for (p = registered; *p; ++p)
				free(*p);
			free(registered);
		}
	}

	return true;
}

bool
dbus_bridge_port_acquire_name(dbus_bridge_port_t *port, const char *name)
{
	dbus_service_proxy_t **pos, *proxy;

	for (pos = &port->service_proxies; (proxy = *pos) != NULL; pos = &proxy->next) {
		if (!strcmp(proxy->name, name)) {
			log_debug("%s: already have a proxy for %s", port->name, name);
			break;
		}
	}

	if (proxy == NULL)
		*pos = proxy = dbus_service_proxy_new(name, port->bus_address);

	if (!dbus_service_proxy_connect(proxy, port)) {
		log_error("Unable to establish a %s proxy connection for %s", port->name, proxy->name);

		if (proxy->dbus)
			dbus_client_disconnect(proxy->dbus);

		return false;
	}

	return true;
}

void
dbus_bridge_port_release_name(dbus_bridge_port_t *port, const char *name)
{
	dbus_service_proxy_t **pos, *proxy;

	for (pos = &port->service_proxies; (proxy = *pos) != NULL; pos = &proxy->next) {
		if (!strcmp(proxy->name, name)) {
			log_debug("%s: we have a proxy for %s", port->name, name);
			if (proxy->dbus) {
				log_debug("%s: deactivating proxy for %s", port->name, name);
				proxy->dbus->state = STATE_SHUTTING_DOWN;
			}
			break;
		}
	}
}

void
dbus_bridge_port_event_name_lost(dbus_bridge_port_t *port, const char *name)
{
	if (port->other == NULL)
		return;

	dbus_bridge_port_release_name(port->other, name);
}

void
dbus_bridge_port_event_name_acquired(dbus_bridge_port_t *port, const char *name)
{
	if (port->other == NULL)
		return;

	if (strutil_array_contains(&port->names_to_publish, name))
		dbus_bridge_port_acquire_name(port->other, name);
}

int
main(int argc, char **argv)
{
	dbus_bridge_port_t *port_upstream, *port_downstream;
	sd_event *event = NULL;

	tracing_set_level(1);

	if (sd_event_default(&event) < 0)
		log_fatal("Unable to create sd-event loop");

	port_upstream = dbus_bridge_port_new("upstream", NULL);
	port_downstream = dbus_bridge_port_new("downstream", "/tmp/downstream");
	port_upstream->other = port_downstream;
	port_downstream->other = port_upstream;

	dbus_bridge_port_publish(port_upstream, "org.freedesktop.NetworkManager");
#if 0
	dbus_bridge_port_publish(port_upstream, "org.fedoraproject.FirewallD1");
	dbus_bridge_port_publish(port_upstream, "net.hadess.PowerProfiles");
#endif
	dbus_bridge_port_publish(port_upstream, "com.intel.tss2.Tabrmd");

	if (1) {
		if (!dbus_bridge_port_monitor(port_downstream, true))
			return 1;
	}

	if (1) {
		if (!dbus_bridge_port_monitor(port_upstream, false))
			return 1;

		dbus_bridge_port_list_names(port_upstream);
	}

	sd_event_loop(event);
	return 0;
}

