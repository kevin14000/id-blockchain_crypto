#makefile

SRCDIR=src
HEADDIR=inc
LIBDIR=obj
BINDIR=bin

CC=gcc
CFLAGS=-I$(HEADDIR) -g -Wall -pedantic -Os
LDFLAGS=-lssl -lcrypto
 
# Les différents sources *.c
SRC=$(wildcard $(SRCDIR)/*.c)
# Les objets correspondants à créer
OBJ=$(SRC:$(SRCDIR)/%.c=$(LIBDIR)/%.o)
# Les exécutables à créer
BIN=$(BINDIR)/test
 
all: $(BIN) ExecuteTest

#Création des exécutables
$(BIN): $(OBJ)
	$(CC) -o $(BIN) $^ $(CFLAGS) $(LDFLAGS)
 
# Création des différents *.o à partir des *.c
$(LIBDIR)/%.o: $(SRCDIR)/%.c $(HEADDIR)/*.h 
	$(CC) -o $@ -c $< $(CFLAGS)
	
ExecuteTest:
	./$(BINDIR)/test
 
# Nettoyage
clean:
	rm $(LIBDIR)/*.o
 
# Nettoyage complet
Clean: clean
	rm $(BINDIR)/*
