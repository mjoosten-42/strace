FILES = $(basename $(shell find . -name '*.s'))

all: $(FILES)

$(FILES): %: %.s
	nasm -f elf64 -o $@.o $< && ld -o $@ $@.o

clean:
	$(RM) *.o

fclean: clean
	$(RM) $(FILES)

re:
	$(MAKE) fclean
	$(MAKE) all

