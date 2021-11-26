CFLAGS=-shared

STRIP?=strip

debug: CFLAGS += -g -O0
debug: winpty.dll

release: CFLAGS += -O2
release: winpty.dll
	$(STRIP) --strip-unneeded $<

winpty.dll: winpty.c util.h
	$(CC) -o $@ $< ${CFLAGS}

dist: release
	mkdir -p bin
	cp winpty.dll bin
	tar -czf winpty.tar.gz bin include

clean:
	rm -rf bin
	rm -f *.dll *.tar.gz

.PHONY: debug release dist clean