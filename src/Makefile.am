HELP2MAN = help2man -N -s1 -S '$(PACKAGE_STRING)'

WARNINGS = -Wall -Wextra -W -Wshadow -Wcast-align \
	-Wwrite-strings -Wconversion -Waggregate-return -Wstrict-prototypes \
	-Wmissing-prototypes -Wmissing-declarations -Wmissing-noreturn \
	-Wmissing-format-attribute -Wredundant-decls -Wdisabled-optimization \
	\
	-Wno-pointer-arith

if USE_WERROR
WARNINGS += -Werror
endif

AM_CPPFLAGS = -g -std=c99 -D_DEFAULT_SOURCE \
	$(WARNINGS)

AM_CPPFLAGS += -I$(srcdir)/block-gost -I$(builddir)/block-gost
AM_YFLAGS = -d

bin_PROGRAMS = osec osec2txt txt2osec
osec_SOURCES = osec.c osec.h \
		common.c memory.c privs.c status.c digest.c dbvalue.c \
		dbversion.c exclude.c ignore.c path.c \
                block-gost/gost.c block-gost/gost.h block-gost/const.h
#dist_man_MANS = $(bin_PROGRAMS:=.1)

osec2txt_SOURCES = osec2txt.c
osec2txt_LDADD = common.o memory.o dbvalue.o dbversion.o digest.o block-gost/gost.o

BUILT_SOURCES = txt2osec.h txt2osec.c
txt2osec_SOURCES = txt2osec.y txt2osec.analize.l
txt2osec_CFLAGS = -Wno-conversion
txt2osec_LDADD = common.o memory.o dbvalue.o digest.o block-gost/gost.o dbversion.o

CLEANFILES = $(bin_PROGRAMS) $(bin_PROGRAMS:=.1)

%.1: % %.1.inc
	$(HELP2MAN) -i $@.inc ./$< >$@
