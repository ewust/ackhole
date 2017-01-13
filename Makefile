

CFLAGS+=-g
LDFLAGS+=-lpcap -levent -levent_extra -levent_openssl -lssl -lm

all: ackhole

ackhole: ackhole.c logger.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
