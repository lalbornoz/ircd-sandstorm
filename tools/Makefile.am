# $Id: Makefile.am 25273 2008-04-23 19:59:46Z androsyn $ 

bin_PROGRAMS = ratbox-mkpasswd
AM_CFLAGS=$(WARNFLAGS)

INCLUDES = $(DEFAULT_INCLUDES) -I../libratbox/include -I.


ratbox_mkpasswd_SOURCES = mkpasswd.c

ratbox_mkpasswd_LDADD = ../libratbox/src/libratbox.la

