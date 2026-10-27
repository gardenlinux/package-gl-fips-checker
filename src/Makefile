CC     ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
TARGET := gl-fips-checker
SRC    := gl-fips-checker.c
LIBS   := -lssl -lcrypto

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)
