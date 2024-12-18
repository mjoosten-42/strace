NAMES = main

all: $(NAMES)

$(NAMES): %: %.s
	nasm -f elf64 $< -o $@.o && ld $@.o -o $@

clean:
	$(RM) -f %.o

fclean:
	$(RM) -f $(NAMES)

