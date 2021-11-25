CFLAGS=-shared

STRIP?=strip

debug: CFLAGS += -g -O0
debug: winpty.dll

release: CFLAGS += -O2
release: winpty.dll
	$(STRIP) --strip-unneeded $<

winpty.dll: winpty.c winpty.h util.h
	$(CC) -o $@ $< ${CFLAGS}

.PHONY: debug release