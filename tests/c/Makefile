FILES = $(basename $(shell find . -name '*.c'))

all: $(FILES)

$(FILES): %: %.c
	$(CC) -g -o $@ $<

clean:
	$(RM) *.o

fclean: clean
	$(RM) $(FILES)

re:
	$(MAKE) fclean
	$(MAKE) all

