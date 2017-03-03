CC=gcc
CFLAGS=-c -Wall -I../common -I../common/network
LDFLAGS=-Wall -I../common -I../common/network -L../common
LIBS=-pthread -ludp-hp-common

SOURCES=sign_in_hp_endpoint.c

OBJECTS=$(SOURCES:.c=.o)

EXECUTABLE=server_sign_in

DEPENDENCIES=../common

define get_objs =
`ls $(1)/*.o`
endef

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): dependencies $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(foreach dir, $(DEPENDENCIES), $(call get_objs,$(dir))) -o $@ $(LIBS)

%.o : %.c
	$(CC) $(CFLAGS) $< -o $@

.PHONY: dependencies $(DEPENDENCIES)

dependencies: $(DEPENDENCIES)

$(DEPENDENCIES):
	$(MAKE) -C $@ all

clean:
	rm -f *o $(EXECUTABLE)
	for dir in $(DEPENDENCIES); do \
	$(MAKE) -C $$dir clean; \
	done