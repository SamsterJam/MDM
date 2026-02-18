CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lpam -lsystemd

PREFIX = /usr
BINDIR = $(PREFIX)/bin
CONFDIR = /etc/mdm
PAMDIR = /etc/pam.d
SHAREDIR = $(PREFIX)/share/mdm

TARGET = mdm
SRCDIR = src
BUILDDIR = build
SOURCES = $(SRCDIR)/mdm.c $(SRCDIR)/figlet.c $(SRCDIR)/config.c $(SRCDIR)/tui.c
OBJECTS = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SOURCES))

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

clean:
	rm -f $(TARGET)
	rm -rf $(BUILDDIR)

install: $(TARGET)
	@echo "Installing $(TARGET)..."
	@echo "Creating directories..."
	mkdir -p $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)/usr/lib/systemd/system
	mkdir -p $(DESTDIR)/usr/lib/systemd/system/getty@tty1.service.d
	mkdir -p $(DESTDIR)$(PAMDIR)
	mkdir -p $(DESTDIR)$(SHAREDIR)
	mkdir -p $(DESTDIR)$(CONFDIR)
	mkdir -p $(DESTDIR)/var/cache/mdm
	@echo "Installing files..."
	install -m755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	install -m644 mdm.service $(DESTDIR)/usr/lib/systemd/system/mdm.service
	install -m644 getty@tty1.service.d/noclear.conf $(DESTDIR)/usr/lib/systemd/system/getty@tty1.service.d/noclear.conf
	install -m644 pam.d/mdm $(DESTDIR)$(PAMDIR)/mdm
	install -m644 assets/standard.flf $(DESTDIR)$(SHAREDIR)/standard.flf
	install -m644 assets/small.flf $(DESTDIR)$(SHAREDIR)/small.flf
	install -m644 assets/mini.flf $(DESTDIR)$(SHAREDIR)/mini.flf
	install -m644 mdm.conf $(DESTDIR)$(CONFDIR)/mdm.conf
	@echo ""
	@echo "Installation complete! To enable:"
	@echo "  sudo systemctl enable mdm"
	@echo "  sudo systemctl start mdm"
	@echo "  Edit /etc/mdm/mdm.conf to customize colors"
	@echo ""

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)/usr/lib/systemd/system/mdm.service
	rm -f $(DESTDIR)/usr/lib/systemd/system/getty@tty1.service.d/noclear.conf
	rmdir --ignore-fail-on-non-empty $(DESTDIR)/usr/lib/systemd/system/getty@tty1.service.d
	rm -f $(DESTDIR)$(PAMDIR)/mdm
	rm -f $(DESTDIR)$(SHAREDIR)/standard.flf
	rm -f $(DESTDIR)$(SHAREDIR)/small.flf
	rm -f $(DESTDIR)$(SHAREDIR)/mini.flf
	@echo "Note: $(CONFDIR)/mdm.conf and /var/cache/mdm left intact for safety"

.PHONY: all clean install uninstall
