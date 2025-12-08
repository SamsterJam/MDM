CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lpam

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
CONFDIR = /etc/termdm
PAMDIR = /etc/pam.d

TARGET = termdm

all: $(TARGET)

$(TARGET): termdm.c
	$(CC) $(CFLAGS) -o $(TARGET) termdm.c $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	@echo "Installing $(TARGET)..."
	install -Dm755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	install -Dm644 termdm.service $(DESTDIR)/etc/systemd/system/termdm.service
	install -Dm644 pam.d/termdm $(DESTDIR)$(PAMDIR)/termdm
	@echo ""
	@echo "Installation complete! To enable:"
	@echo "  sudo systemctl enable termdm"
	@echo "  sudo systemctl start termdm"
	@echo ""
	@echo "TermDM will auto-detect users and sessions - no config needed!"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)/etc/systemd/system/termdm.service
	rm -f $(DESTDIR)$(PAMDIR)/termdm
	@echo "Note: $(CONFDIR)/config left intact for safety"

.PHONY: all clean install uninstall
