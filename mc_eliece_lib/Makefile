# mc_eliece_lib/Makefile
# Compiles the four McEliece C binaries into mc_eliece_lib/binaries/
#
# Requires:  gcc, make
# Usage:     cd mc_eliece_lib && make

CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=c11 -Isrc
BINDIR  = binaries
SRCDIR  = src

TARGETS = $(BINDIR)/keygen \
          $(BINDIR)/find_H \
          $(BINDIR)/encryption \
          $(BINDIR)/decryption

.PHONY: all clean

all: $(BINDIR) $(TARGETS)
	@echo "Build complete. Binaries in $(BINDIR)/"

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINDIR)/keygen: $(SRCDIR)/keygen.c $(SRCDIR)/matrix.h
	$(CC) $(CFLAGS) $(SRCDIR)/keygen.c -o $@

$(BINDIR)/find_H: $(SRCDIR)/find_H.c $(SRCDIR)/matrix.h
	$(CC) $(CFLAGS) $(SRCDIR)/find_H.c -o $@

$(BINDIR)/encryption: $(SRCDIR)/encryption.c $(SRCDIR)/matrix.h
	$(CC) $(CFLAGS) $(SRCDIR)/encryption.c -o $@

$(BINDIR)/decryption: $(SRCDIR)/decryption.c $(SRCDIR)/matrix.h
	$(CC) $(CFLAGS) $(SRCDIR)/decryption.c -o $@

clean:
	rm -rf $(BINDIR)
