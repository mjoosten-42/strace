NAMES = $(basename $(shell find . -name '*.s'))

all: $(NAMES)

$(NAMES): %: %.s
	nasm -f elf64 $< -o $@.o && ld $@.o -o $@

clean:
	$(RM) *.o

fclean:
	$(RM) $(NAMES)

