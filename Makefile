MODULE_big = libx509pq
OBJS = libx509pq.o
EXTENSION = libx509pq
DATA = libx509pq--1.1.sql libx509pq--1.0--1.1.sql
REGRESS = basic
REGRESS_OPTS = --inputdir=test --outputdir=test
PG_CPPFLAGS = -Wno-declaration-after-statement
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
SHLIB_LINK = -lcrypto
