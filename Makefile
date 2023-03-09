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
CFLAGS		= -Wall -D_GNU_SOURCE $(COPT) -Wformat-truncation=0
WORMHOLE	= wormhole
WORMHOLE_SRCS	= wormhole.c
WORMHOLE_OBJS	= $(WORMHOLE_SRCS:.c=.o)
LINK		= -L. -lwormhole -lutil

IMGDELTA	= imgdelta
IMGDELTA_SRCS	= imgdelta.c
IMGDELTA_OBJS	= $(IMGDELTA_SRCS:.c=.o)

LIB		= libwormhole.a
LIB_SRCS	= \
		  layer.c \
		  fstree.c \
		  mntent2.c \
		  tracing.c \
		  util.c
LIB_OBJS	= $(LIB_SRCS:.c=.o)

_MAN1PAGES	= wormhole.1 \
		  wormhole-digger.1 \
		  wormhole-autoprofile.1
_MAN5PAGES	= wormhole.conf.5
_MAN8PAGES	= wormholed.8

all: $(WORMHOLE) $(IMGDELTA)

clean:
	rm -f $(WORMHOLE)
	rm -f *.o *.a

install: $(WORMHOLE)
	@case "$(DESTDIR)" in \
	""|/*) ;; \
	*) echo "DESTDIR is a relative path, no workie" >&2; exit 2;; \
	esac
	install -m 755 -d $(DESTDIR)$(BINDIR)
	install -m 555 -s $(WORMHOLE) $(DESTDIR)$(BINDIR)
	install -m 555 -s $(IMGDELTA) $(DESTDIR)$(BINDIR)
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

$(WORMHOLE): $(WORMHOLE_OBJS) $(LIB)
	$(CC) $(CFLAGS) -o $@ $(WORMHOLE_OBJS) $(LINK)

$(IMGDELTA): $(IMGDELTA_OBJS) $(LIB)
	$(CC) $(CFLAGS) -o $@ $(IMGDELTA_OBJS) $(LINK)

$(LIB): $(LIB_OBJS)
	$(AR) crv $@  $(LIB_OBJS)

ifeq ($(wildcard .depend), .depend)
include .depend
endif

depend:
	gcc $(CFLAGS) -MM *.c >.depend

dist:
	mkdir wormhole-$(VERSION)
	cp $$(git ls-files) wormhole-$(VERSION)
	tar cvjf wormhole-$(VERSION).tar.bz2 wormhole-$(VERSION)/
	rm -rf wormhole-$(VERSION)
