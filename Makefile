
SRC_DIR = $(shell pwd)

CC    := $(COMPILER_PREFIX)gcc
CXX   := $(COMPILER_PREFIX)g++
AR    := $(COMPILER_PREFIX)ar
STRIP := $(COMPILER_PREFIX)strip

DESTDIR ?= ./destdir


SOURCES   := log_trace.c

INCLUDES  := log_trace_color.h \
             log_trace.h

DEFINEDS  :=

CFLAGS += -Wall \
          -fPIC \
          -g

LDFLAGS :=

TARGET := liblt

OBJ_DIR := obj

OBJ_LIB := -Lobj \
           -llt

INC_DIR := -I$(SRC_DIR)

OBJ_CFLAGS := $(DEFINDES) \
              $(INC_DIR) \
              -c \
              $(CFLAGS)

OBJ_LDFLAGS := $(LDFLAGS) \
               $(LIB_PATH)


OBJ_SRC    := $(SOURCES:%.c=$(OBJ_DIR)/%.o)

.PHONY: all lib clean install

all:
	make clean
	make lib
	make bin

$(OBJ_DIR)/%.o : %.c
	@echo "mkdir $(OBJ_DIR)..."
	@mkdir -p $(SRC_DIR)/$(OBJ_DIR)
	$(CC) -c $(OBJ_CFLAGS) -o $@ $<

bin:
	@echo "Compile..."
	$(CC) -o $(OBJ_DIR)/test_lt test_lt.c $(OBJ_LIB) -lpthread $(OBJ_LDFLAGS) -Wl,-Map=$(OBJ_DIR)/$(TARGET).map

lib: $(OBJ_SRC)
	@echo "Compile...Library"
	$(CC) -shared -Wl,-soname,$(OBJ_DIR)/$(TARGET).so -o $(OBJ_DIR)/$(TARGET).so $(OBJ_SRC)
	$(AR) -r $(OBJ_DIR)/$(TARGET).a $(OBJ_SRC)

clean:
	@echo "Clean $(SRC_DIR)/$(OBJ_DIR)..."
	rm -rvf $(SRC_DIR)/$(OBJ_DIR)

install:
	@echo "DEST Path = $(DESTDIR)"
	install -d $(DESTDIR)/inc
	install -d $(DESTDIR)/lib
	install -m 644 $(INCLUDES) $(DESTDIR)/inc
	install -m 644 $(OBJ_DIR)/$(TARGET).a $(DESTDIR)/lib
	# install -m 644 $(OBJ_DIR)/$(TARGET).so $(DESTDIR)/lib
