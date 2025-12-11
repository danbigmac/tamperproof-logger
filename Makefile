# Compiler and flags
CC       := gcc
CFLAGS   := -Wall -Wextra -Werror -std=c11 -Iinclude -O2 -MMD -MP
LDFLAGS  := -lsodium -lz

# Directories
SRC_DIR   := src
INC_DIR   := include
BUILD_DIR := build
BIN       := $(BUILD_DIR)/logger

# Application entry point
APP_SRC   := $(SRC_DIR)/main.c

# Source and object discovery
ALL_SRCS  := $(wildcard $(SRC_DIR)/*.c)
LIB_SRCS  := $(filter-out $(APP_SRC),$(ALL_SRCS))

MAIN_OBJ  := $(BUILD_DIR)/main.o
LIB_OBJS  := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(LIB_SRCS))

OBJS      := $(MAIN_OBJ) $(LIB_OBJS)
DEPS      := $(OBJS:.o=.d)

# Default target
all: $(BIN)

# Build executable
$(BIN): $(OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(OBJS) -o $(BIN) $(LDFLAGS)
	@echo "Build complete - $(BIN)"

# Compile main.c separately
$(BUILD_DIR)/main.o: $(APP_SRC)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile other .c files into .o (+ auto dependency generation)
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Include dependency files if they exist
-include $(DEPS)

# Clean build directory
clean:
	rm -rf $(BUILD_DIR)

# Run program
run: $(BIN)
	$(BIN)

# Debug build
debug: CFLAGS := -Wall -Wextra -Werror -std=c11 -Iinclude -g -MMD -MP
debug: clean all

# Tests
TEST_DIR   := tests
TESTS      := $(wildcard $(TEST_DIR)/*.c)
TEST_BINS  := $(patsubst $(TEST_DIR)/%.c,$(BUILD_DIR)/test_%,$(TESTS))

test: $(TEST_BINS)
	@echo "Running tests..."
	@for t in $(TEST_BINS); do echo "==> $$t"; $$t; done

# Link each test with LIB_OBJS (no main.o!)
$(BUILD_DIR)/test_%: $(TEST_DIR)/%.c $(LIB_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $< $(LIB_OBJS) -o $@ $(LDFLAGS)

.PHONY: all clean run debug test
