MODULE_big = libx509pq
OBJS = libx509pq.o name.o extensions.o crypto.o basic_info.o
EXTENSION = libx509pq
DATA = libx509pq--1.2.sql libx509pq--1.1--1.2.sql libx509pq--1.1.sql libx509pq--1.0--1.1.sql
REGRESS = basic
REGRESS_OPTS = --inputdir=test --outputdir=test
PG_CPPFLAGS = -Wno-declaration-after-statement
PG_CONFIG = pg_config

ifdef OPENSSL_HOME
PG_CPPFLAGS += -I$(OPENSSL_HOME)/include
OPENSSL_LIBDIR := $(firstword $(wildcard $(OPENSSL_HOME)/lib64 $(OPENSSL_HOME)/lib))
SHLIB_LINK = $(OPENSSL_LIBDIR)/libcrypto.so -Wl,-rpath,$(OPENSSL_LIBDIR) -Wl,--disable-new-dtags
else
SHLIB_LINK = -lcrypto
endif

PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
