UNAME := $(shell uname)

RTFLAGS=-lrt
ifeq ($(UNAME), Darwin)
RTFLAGS=-framework CoreServices
endif
OLEVEL=-O2 -DNDEBUG
CFLAGS=-Wall $(OLEVEL) -std=gnu99 -luv
FILES=local.c
APP=js-local

all: $(FILES)
	$(CC) $(CFLAGS) -o \
	$(APP) $(FILES) \
	-lcrypto -lm $(RTFLAGS)
