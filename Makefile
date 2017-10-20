EXTENSION     = pg_blkchain
DATA          = pg_blkchain--0.0.1.sql
TESTS         = $(wildcard test/sql/*.sql)

REGRESS_OPTS  = --inputdir=test             \
                --load-extension=pg_blkchain \
                --load-language=plpgsql
REGRESS       = $(patsubst test/sql/%.sql,%,$(TESTS))
MODULE_big    = pg_blkchain
SRCS        = pg_blkchain.c
OBJS        = $(SRCS:.c=.o)

SHLIB_LINK    += -lccoin

# postgres build stuff
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
