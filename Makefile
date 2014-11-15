# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.

PREFIX ?= /usr
BIN ?= /bin
BINDIR ?= $(PREFIX)$(BIN)
DATA ?= /share
DATADIR ?= $(PREFIX)$(DATA)
LICENSEDIR ?= $(DATADIR)/licenses

PKGNAME = autopasswd
COMMAND = autopasswd

OPTIMISE = -Ofast

WARN = -Wall -Wextra -pedantic -Wdouble-promotion -Wformat=2 -Winit-self -Wmissing-include-dirs  \
       -Wtrampolines -Wfloat-equal -Wshadow -Wmissing-prototypes -Wmissing-declarations          \
       -Wredundant-decls -Wnested-externs -Winline -Wno-variadic-macros -Wswitch-default         \
       -Wsync-nand -Wunsafe-loop-optimizations -Wcast-align -Wstrict-overflow -Wundef            \
       -Wbad-function-cast -Wcast-qual -Wpacked -Wlogical-op -Wstrict-prototypes -Wconversion    \
       -Wold-style-definition -Wvector-operation-performance -Wunsuffixed-float-constants        \
       -Wsuggest-attribute=const -Wsuggest-attribute=noreturn -Wsuggest-attribute=pure           \
       -Wsuggest-attribute=format -Wnormalized=nfkc -Wdeclaration-after-statement

F_OPTS = -ftree-vrp -fstrict-aliasing -fipa-pure-const -fstack-usage -fstrict-overflow        \
         -funsafe-loop-optimizations -fno-builtin

X = 

STD = c99

FLAGS = $(OPTIMISE) -std=$(STD) $(F_OPTS) $(X) -DWITH_C99


.PHONY: all
all: bin/autopasswd

bin/autopasswd: obj/autopasswd.o obj/sha3.o
	@mkdir -p bin
	$(CC) $(FLAGS) -fwhole-program -lpassphrase -largparser -o $@ $^ $(LDFLAGS)

obj/%.o: src/%.c src/sha3.h
	@mkdir -p obj
	$(CC) $(FLAGS) $(WARN) -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

obj/sha3.o: src/sha3.c src/sha3.h
	@mkdir -p obj
	$(CC) $(FLAGS) -c -o $@ $< $(CFLAGS) $(CPPFLAGS)


.PHONY: install
install: bin/autopasswd
	install -dm755 -- "$(DESTDIR)$(BINDIR)"
	install -m755 bin/autopasswd -- "$(DESTDIR)$(BINDIR)/$(COMMAND)"
	install -dm755 -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)"
	install -m644  COPYING LICENSE -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)"

.PHONY: uninstall
uninstall:
	-rm -- "$(DESTDIR)$(BINDIR)/$(COMMAND)"
	-rm -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)/COPYING"
	-rm -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)/LICENSE"
	-rmdir -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)"

.PHONY: clean
clean:
	-rm -r bin obj
