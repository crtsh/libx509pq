MODULE_big = libx509pq
OBJS = libx509pq.o name.o extensions.o crypto.o basic_info.o
EXTENSION = libx509pq
DATA = libx509pq--1.1.sql libx509pq--1.0--1.1.sql
REGRESS = basic
REGRESS_OPTS = --inputdir=test --outputdir=test
PG_CPPFLAGS = -Wno-declaration-after-statement
PG_CONFIG = pg_config

ifdef OPENSSL_HOME
PG_CPPFLAGS += -I$(OPENSSL_HOME)/include
SHLIB_LINK = -L$(OPENSSL_HOME)/lib -Wl,-rpath,$(OPENSSL_HOME)/lib -lcrypto
else
SHLIB_LINK = -lcrypto
endif

PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
