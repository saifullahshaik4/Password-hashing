CC = gcc
CFLAGS = -g -Wall -Wextra -Wshadow -Wunreachable-code \
		-Wredundant-decls -Wmissing-declarations \
		-Wold-style-definition -Wmissing-prototypes \
		-Wdeclaration-after-statement -Wno-return-local-addr \
		-Wunsafe-loop-optimizations -Wuninitialized -Werror \
		-Wno-unused-parameter
PROGS = thread_hash

all: $(PROGS)

$(PROGS): $(PROGS).o
	$(CC) $(CFLAGS) -o $@ $^ -lcrypt

$(PROGS).o: $(PROGS).c $(PROGS).h
	$(CC) $(CFLAGS) -c $<

clean cls:
	rm -f $(PROGS) *.o *~ \#~

git:
	git add $(PROGS).c $(PROGS).h [mM]akefile
	git status

make_tar:
	tar cvfa Lab4_${LOGNAME}.tar.gz $(PROGS).c $(PROGS).h [mM]akefile





