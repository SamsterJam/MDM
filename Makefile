CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lpam

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
CONFDIR = /etc/mdm
PAMDIR = /etc/pam.d
SHAREDIR = $(PREFIX)/share/mdm

TARGET = mdm
SRCDIR = src
BUILDDIR = build
SOURCES = $(SRCDIR)/mdm.c $(SRCDIR)/figlet.c $(SRCDIR)/config.c
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
	install -Dm755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	install -Dm644 mdm.service $(DESTDIR)/etc/systemd/system/mdm.service
	install -Dm644 pam.d/mdm $(DESTDIR)$(PAMDIR)/mdm
	install -Dm644 assets/standard.flf $(DESTDIR)$(SHAREDIR)/standard.flf
	install -Dm644 assets/small.flf $(DESTDIR)$(SHAREDIR)/small.flf
	install -Dm644 assets/mini.flf $(DESTDIR)$(SHAREDIR)/mini.flf
	install -Dm644 mdm.conf $(DESTDIR)$(CONFDIR)/mdm.conf
	@echo ""
	@echo "Installation complete! To enable:"
	@echo "  sudo systemctl enable mdm"
	@echo "  sudo systemctl start mdm"
	@echo "  Edit /etc/mdm/mdm.conf to customize colors"
	@echo ""

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)/etc/systemd/system/mdm.service
	rm -f $(DESTDIR)$(PAMDIR)/mdm
	rm -f $(DESTDIR)$(SHAREDIR)/standard.flf
	rm -f $(DESTDIR)$(SHAREDIR)/small.flf
	rm -f $(DESTDIR)$(SHAREDIR)/mini.flf
	@echo "Note: $(CONFDIR)/mdm.conf left intact for safety"

.PHONY: all clean install uninstall
