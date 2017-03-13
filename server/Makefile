CC=gcc
CFLAGS=-c -Wall -I../common -I../common/network
LDFLAGS=-Wall -I../common -I../common/network -L../common
LIBS=-pthread -ludp-hp-common

THE_SRV_SOURCES=the_server.c
SIGN_IN_SOURCES=sign_in_hp_endpoint.c
CHAT_SOURCES=chat_hp_endpoint.c

THE_SRV_OBJECTS=$(THE_SRV_SOURCES:.c=.o)
SIGN_IN_OBJECTS=$(SIGN_IN_SOURCES:.c=.o)
CHAT_OBJECTS=$(CHAT_SOURCES:.c=.o)

THE_SRV_EXECUTABLE=the_server
SVR_SIGN_IN_EXECUTABLE=server_sign_in
SVR_CHAT_EXECUTABLE=server_chat

DEPENDENCIES=../common

define get_objs =
`ls $(1)/*.o`
endef

all: $(SOURCES) $(THE_SRV_EXECUTABLE) $(SVR_SIGN_IN_EXECUTABLE) $(SVR_CHAT_EXECUTABLE)

$(THE_SRV_EXECUTABLE): dependencies $(THE_SRV_OBJECTS)
	$(CC) $(LDFLAGS) $(THE_SRV_OBJECTS) $(foreach dir, $(DEPENDENCIES), $(call get_objs,$(dir))) -o $@ $(LIBS)

$(SVR_SIGN_IN_EXECUTABLE): dependencies $(SIGN_IN_OBJECTS)
	$(CC) $(LDFLAGS) $(SIGN_IN_OBJECTS) $(foreach dir, $(DEPENDENCIES), $(call get_objs,$(dir))) -o $@ $(LIBS)

$(SVR_CHAT_EXECUTABLE): dependencies $(CHAT_OBJECTS)
	$(CC) $(LDFLAGS) $(CHAT_OBJECTS) $(foreach dir, $(DEPENDENCIES), $(call get_objs,$(dir))) -o $@ $(LIBS)

%.o : %.c
	$(CC) $(CFLAGS) $< -o $@

.PHONY: dependencies $(DEPENDENCIES)

dependencies: $(DEPENDENCIES)

$(DEPENDENCIES):
	$(MAKE) -C $@ all

clean:
	rm -f *o $(THE_SRV_EXECUTABLE) $(SVR_SIGN_IN_EXECUTABLE) $(SVR_CHAT_EXECUTABLE)
	for dir in $(DEPENDENCIES); do \
	$(MAKE) -C $$dir clean; \
	done