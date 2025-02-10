FILES = $(basename $(shell find . -name '*.s' ! -name "defines.s"))

all: $(FILES)

$(FILES): %: %.s defines.s
	nasm -f elf64 -o $@.o $< && ld -o $@ $@.o

clean:
	$(RM) *.o

fclean: clean
	$(RM) $(FILES)

re:
	$(MAKE) fclean
	$(MAKE) all

