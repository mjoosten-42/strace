FILES = $(basename $(shell find . -name '*.s' ! -name "defines.s"))

all: $(FILES)

$(FILES): %: %.s defines.s
	nasm -f elf32 -o $@.o $< && ld -m elf_i386 -o $@ $@.o

clean:
	$(RM) *.o

fclean: clean
	$(RM) $(FILES)

re:
	$(MAKE) fclean
	$(MAKE) all
