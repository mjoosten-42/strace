NAME = a.out

all: $(NAME)

$(NAME): libclang.c
	$(CC) -g libclang.c -I ~/.capt/root/usr/lib/llvm-15/include/ ~/.capt/root/usr/lib/x86_64-linux-gnu/libclang-15.so
#	$(CC) -g libclang.c -I /usr/lib/llvm-14/include/ /usr/lib/llvm-14/lib/libclang.so

clean:

fclean: clean
	$(RM) $(NAME)

re:
	$(MAKE) fclean
	$(MAKE) all

