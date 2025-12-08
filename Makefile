CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lpam

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
CONFDIR = /etc/mdm
PAMDIR = /etc/pam.d
SHAREDIR = $(PREFIX)/share/mdm

TARGET = mdm
SOURCES = mdm.c ascii.c
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJECTS)

install: $(TARGET)
	@echo "Installing $(TARGET)..."
	install -Dm755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	install -Dm644 mdm.service $(DESTDIR)/etc/systemd/system/mdm.service
	install -Dm644 pam.d/mdm $(DESTDIR)$(PAMDIR)/mdm
	install -Dm644 standard.flf $(DESTDIR)$(SHAREDIR)/standard.flf
	@echo ""
	@echo "Installation complete! To enable:"
	@echo "  sudo systemctl enable mdm"
	@echo "  sudo systemctl start mdm"
	@echo ""
	@echo "MDM will auto-detect users and sessions - no config needed!"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)/etc/systemd/system/mdm.service
	rm -f $(DESTDIR)$(PAMDIR)/mdm
	rm -f $(DESTDIR)$(SHAREDIR)/standard.flf
	@echo "Note: $(CONFDIR)/config left intact for safety"

.PHONY: all clean install uninstall
