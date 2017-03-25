CC=gcc
CFLAGS=-c -Wall
AR=ar
ARFLAGS=rcs

SOURCES=common.c node.c hashtable.c

OBJECTS=$(SOURCES:.c=.o)

STATIC_LIB=libudp-hp-common.a

DEPENDENCIES=network \
		crypto_wrapper

define get_objs =
`ls $(1)/*.o`
endef

all: $(SOURCES) $(STATIC_LIB)

$(STATIC_LIB): dependencies $(OBJECTS)
	$(AR) $(ARFLAGS) $@ $(OBJECTS) $(foreach dir, $(DEPENDENCIES), $(call get_objs,$(dir)))

%.o : %.c
	$(CC) $(CFLAGS) $< -o $@

.PHONY: dependencies $(DEPENDENCIES)

dependencies: $(DEPENDENCIES)

$(DEPENDENCIES):
	$(MAKE) -C $@ all

clean:
	rm -f *o $(STATIC_LIB)
	for dir in $(DEPENDENCIES); do \
	$(MAKE) -C $$dir clean; \
	done