# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.

OPTIMISE = -O0

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

FLAGS = $(OPTIMISE) -std=$(STD) $(F_OPTS) $(X) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -DWITH_C99


all: bin/autopasswd

bin/autopasswd: obj/autopasswd.o obj/sha3.o
	@mkdir -p bin
	$(CC) $(FLAGS) -fwhole-program -lpassphrase -largparser -o $@ $^

obj/%.o: src/%.c src/sha3.h
	@mkdir -p obj
	$(CC) $(FLAGS) $(WARN) -c -o $@ $<

obj/sha3.o: src/sha3.c src/sha3.h
	@mkdir -p obj
	$(CC) $(FLAGS) -c -o $@ $<


clean:
	-rm -r bin obj
