VERSION		= 2.0

BINDIR		= /usr/bin
SBINDIR		= /usr/sbin
ETCDIR		= /etc/wormhole
PROFILEDIR	= /etc/wormhole.d
IMGDIR		= /usr/lib/sysimage/platform
MAN1DIR		= /usr/share/man/man1
MAN5DIR		= /usr/share/man/man5
MAN8DIR		= /usr/share/man/man8
VARLIBDIR	= /var/lib/wormhole

COPT		= -g
CFLAGS		= -Wall -D_GNU_SOURCE $(COPT) -Wformat-truncation=0 -I.
WORMHOLE	= wormhole
WORMHOLE_SRCS	= wormhole.c
WORMHOLE_OBJS	= $(WORMHOLE_SRCS:.c=.o)
BOOTPREP	= boot-prep.sh

LIBDEPS		= $(LIBWORMHOLE) $(LIBOWL)
LINK		= -L. -lowl -lsystemd -lwormhole -lutil

IMGDELTA	= imgdelta
IMGDELTA_SRCS	= imgdelta.c
IMGDELTA_OBJS	= $(IMGDELTA_SRCS:.c=.o)

DBUSRELAY	= dbus-relay
DBUSRELAY_SRCS	= dbus.c \
		  forwarder.c
DBUSRELAY_OBJS	= $(DBUSRELAY_SRCS:.c=.o)

LIBWORMHOLE	= libwormhole.a
LIBWH_SRCS	= \
		  layer.c \
		  discovery.c \
		  mountfarm.c \
		  fstree.c \
		  mntent2.c \
		  tracing.c \
		  util.c
LIBWH_OBJS	= $(LIBWH_SRCS:.c=.o)

LIBOWL		= libowl.a
_LIBOWL_SRCS	= \
		  mainloop.c \
		  bufparser.c \
		  queue.c \
		  endpoint.c \
		  timers.c \
		  socket.c
LIBOWL_SRCS	= $(addprefix $(LIBOWL_SRCDIR)/,$(_LIBOWL_SRCS))
LIBOWL_OBJS	= $(LIBOWL_SRCS:.c=.o)
LIBOWL_SRCDIR	= owl

SCRIPTS		= wormhole-image

_MAN1PAGES	= wormhole.1 \
		  wormhole-digger.1 \
		  wormhole-autoprofile.1
_MAN5PAGES	= wormhole.conf.5
_MAN8PAGES	= wormholed.8

all: $(WORMHOLE) $(IMGDELTA) $(DBUSRELAY)

clean:
	rm -f $(WORMHOLE) $(LIBWORMHOLE) $(LIBOWL)
	rm -f *.o *.a
	rm -f $(LIBOWL_SRCDIR)/*.o

install: $(WORMHOLE) $(IMGDELTA) $(DBUSRELAY)
	@case "$(DESTDIR)" in \
	""|/*) ;; \
	*) echo "DESTDIR is a relative path, no workie" >&2; exit 2;; \
	esac
	install -m 755 -d $(DESTDIR)$(BINDIR)
	install -m 555 -s $(WORMHOLE) $(DESTDIR)$(BINDIR)
	install -m 555 -s $(IMGDELTA) $(DESTDIR)$(BINDIR)
	install -m 555 -s $(DBUSRELAY) $(DESTDIR)$(BINDIR)
	install -m 555 $(SCRIPTS) $(DESTDIR)$(BINDIR)
	install -m 755 -d $(DESTDIR)$(ETCDIR)
	install -m 755 $(BOOTPREP) $(DESTDIR)$(ETCDIR)/boot-prep.sh
ifneq ($(MAN1PAGES),)
	install -m 755 -d $(DESTDIR)$(MAN1DIR)
	install -m 444 $(MAN1PAGES) $(DESTDIR)$(MAN1DIR)
endif
ifneq ($(MAN5PAGES),)
	install -m 755 -d $(DESTDIR)$(MAN5DIR)
	install -m 444 $(MAN5PAGES) $(DESTDIR)$(MAN5DIR)
endif
ifneq ($(MAN8PAGES),)
	install -m 755 -d $(DESTDIR)$(MAN8DIR)
	install -m 444 $(MAN8PAGES) $(DESTDIR)$(MAN8DIR)
endif
	install -m 755 -d $(DESTDIR)$(VARLIBDIR)
	cp -av varlib/* $(DESTDIR)$(VARLIBDIR)

$(WORMHOLE): $(WORMHOLE_OBJS) $(LIBDEPS)
	$(CC) $(CFLAGS) -o $@ $(WORMHOLE_OBJS) $(LINK)

$(IMGDELTA): $(IMGDELTA_OBJS) $(LIBDEPS)
	$(CC) $(CFLAGS) -o $@ $(IMGDELTA_OBJS) $(LINK)

$(DBUSRELAY): $(DBUSRELAY_OBJS) $(LIBDEPS)
	$(CC) $(CFLAGS) -o $@ $(DBUSRELAY_OBJS) $(LINK)

$(LIBWORMHOLE): $(LIBWH_OBJS)
	$(AR) crv $@  $(LIBWH_OBJS)

$(LIBOWL): $(LIBOWL_OBJS)
	$(AR) crv $@  $(LIBOWL_OBJS)

ifeq ($(wildcard .depend), .depend)
include .depend
endif

depend:
	gcc $(CFLAGS) -MM *.c >.depend
	gcc $(CFLAGS) -MM owl/*.c | sed 's:^[a-z]:owl/&:' >>.depend

dist:
	mkdir wormhole-$(VERSION)
	git ls-files | cpio -dlp wormhole-$(VERSION)
	tar cvjf wormhole-$(VERSION).tar.bz2 wormhole-$(VERSION)/
	rm -rf wormhole-$(VERSION)
