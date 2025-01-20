NAMES = $(basename $(shell find . -name '*.s'))

all: $(NAMES)

$(NAMES): %: %.s
	nasm -f elf32 $< -o $@.o && ld -m elf_i386 $@.o -o $@

clean:
	$(RM) *.o

fclean: clean
	$(RM) $(NAMES)

