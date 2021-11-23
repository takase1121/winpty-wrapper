INCS=-Iwinpty/src/include
CFLAGS=${INCS} -shared -O2

STRIP?=strip

debug: CFLAGS += -g
debug: winpty.dll

release: winpty.dll
	$(STRIP) --strip-unneeded $<

winpty.dll: winpty.c
	$(CC) -o $@ $< ${CFLAGS}

.PHONY: debug release