# Compiler
CC = gcc

# Compiler flags
CFLAGS = -03 -Iheaders -Wall -Wextra
CLIBS = -Lextern_libs -lm

# Source and object directories
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin
BIN_NAME = solver.exe

# Gather all source files
SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SOURCES))

# Executable name
TARGET = $(BIN_DIR)/$(BIN_NAME)

# Default rule
all: directories $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(CLIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@ $(CLIBS)

.PHONY: directories
directories:
	@if not exist $(OBJ_DIR) mkdir $(OBJ_DIR)
	@if not exist $(BIN_DIR) mkdir $(BIN_DIR)

.PHONY: run
run:
	./$(BIN_DIR)/$(BIN_NAME)

.PHONY: clean
clean:
	if exist obj rmdir /s /q obj
	if exist bin rmdir /s /q bin
