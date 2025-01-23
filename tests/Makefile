MAKEFILES = $(dir $(shell find . -mindepth 2 -name Makefile))

all: $(MAKEFILES)
	for dir in $(MAKEFILES); do $(MAKE) -C $$dir; done

clean:
	for dir in $(MAKEFILES); do $(MAKE) -C $$dir clean; done

fclean: clean
	for dir in $(MAKEFILES); do $(MAKE) -C $$dir fclean; done

re:
	for dir in $(MAKEFILES); do $(MAKE) -C $$dir re; done
