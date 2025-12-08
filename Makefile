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
	@mkdir -p $(DESTDIR)$(CONFDIR)
	@if [ ! -f $(DESTDIR)$(CONFDIR)/config ]; then \
		install -Dm644 config.example $(DESTDIR)$(CONFDIR)/config; \
		echo "Installed default config to $(CONFDIR)/config"; \
	else \
		echo "Config already exists at $(CONFDIR)/config, not overwriting"; \
	fi
	@echo ""
	@echo "Installation complete! To enable:"
	@echo "  sudo systemctl enable termdm"
	@echo "  sudo systemctl start termdm"
	@echo ""
	@echo "Edit /etc/termdm/config to configure username and session"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)/etc/systemd/system/termdm.service
	rm -f $(DESTDIR)$(PAMDIR)/termdm
	@echo "Note: $(CONFDIR)/config left intact for safety"

.PHONY: all clean install uninstall
