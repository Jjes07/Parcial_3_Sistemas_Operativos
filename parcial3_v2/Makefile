# Makefile para compilar GSEA con soporte POSIX y pthreads

CC = g++
CFLAGS = -Wall -Wextra -O2 -pthread
TARGET = gsea
SRC = GSEA.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

