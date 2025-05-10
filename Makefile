# Makefile for DNS sniffer

CC       := gcc
CFLAGS   := -std=gnu11 -O2 -Wall -Wextra -pthread
LDFLAGS  :=

SRC      := dnsSnifferAgent.c
OBJ      := $(SRC:.c=.o)
TARGET   := dnsSniffer

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean