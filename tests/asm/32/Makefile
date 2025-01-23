FILES = $(basename $(shell find . -name '*.s'))

all: $(FILES)

$(FILES): %: %.s
	nasm -f elf32 -o $@.o $< && ld -m elf_i386 -o $@ $@.o

clean:
	$(RM) *.o

fclean: clean
	$(RM) $(FILES)

re:
	$(MAKE) fclean
	$(MAKE) all
