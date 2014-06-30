

CFLAGS+=-g
LDFLAGS+=-lpcap -levent -lm

all: ackhole

ackhole: ackhole.c logger.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
