NAME = ft_strace 

CC = gcc

CFLAGS  = -Wall -Wextra -Werror -MMD -MP
LDFLAGS = 

SRC_DIR = src
OBJ_DIR = obj
LIB_DIR = lib

export MAKEFLAGS = "-j 8"

include make/sources.mk
include make/headers.mk
include make/include.mk

OBJECTS = $(patsubst $(SRC_DIR)/%,$(OBJ_DIR)/%,$(SOURCES:.c=.o))

DEBUG   ?= 1
VERBOSE ?= 0

ifeq ($(DEBUG), 1)
	CFLAGS += -O0 -g
endif

ifeq ($(VERBOSE), 1)
	CFLAGS += -DVERBOSE
endif

all: $(NAME)

$(NAME): $(OBJECTS)
	$(CC) $(LDFLAGS) $^ -o $@ 

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $@

clean:
	$(RM) -r $(OBJ_DIR)

fclean: clean
	$(RM) $(NAME) $(HOST)

re:
	make fclean
	make all

files:
	./make/make_sources.sh

print: 
	@echo "---SOURCES: $(SOURCES)" | xargs -n1
	@echo "---HEADERS: $(HEADERS)" | xargs -n1
	@echo "---OBJECTS: $(OBJECTS)" | xargs -n1

format: files
	clang-format -i $(SOURCES) $(HEADERS)

ctags:
	ctags $(SOURCES) $(HEADERS)

.PHONY: all test clean fclean re files print format ctags 

-include $(OBJECTS:.o=.d)
