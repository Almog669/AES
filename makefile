# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall

# Source files
SRCS = AES.c AES_funcs.c

# Object files
OBJS = $(SRCS:.c=.o)

# Executable name
EXEC = aes

# Rule to build the executable
$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ -lm

# Rule to compile source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to clean up object files and executable
clean:
	rm -f $(OBJS) $(EXEC)
