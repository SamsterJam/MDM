# TermDM - Minimal Terminal Display Manager

A minimal display manager with a clean TUI for single-user systems.

## Features

- PAM authentication
- Session management with privilege separation
- Dynamic terminal-size-aware UI
- Works with X11 (startx) or Wayland (sway, Hyprland, etc.)

## Installation

```bash
make
sudo make install
sudo nano /etc/termdm/config
sudo systemctl enable termdm
sudo systemctl start termdm
```

## Configuration

Edit `/etc/termdm/config`:

```ini
username=samsterjam
session=startx
```

### Session Examples

```ini
session=startx          # X11 with ~/.xinitrc
session=sway            # Sway
session=Hyprland        # Hyprland
session=startx /usr/bin/i3
```

## Files

- `termdm.c` - Main source
- `termdm.service` - Systemd service unit
- `pam.d/termdm` - PAM configuration
- `config.example` - Example configuration
- `Makefile` - Build and installation

## Troubleshooting

**Authentication failed:**
- Check `/etc/pam.d/termdm` is installed
- Check journal: `journalctl -u termdm -f`

**X server fails:**
- Ensure `~/.xinitrc` exists
- Check X is installed: `which startx`

**Can't see UI:**
- Switch to TTY7: `Ctrl+Alt+F7`
- Check status: `systemctl status termdm`

**Disable other display managers:**
```bash
sudo systemctl disable gdm
sudo systemctl disable sddm
sudo systemctl disable lightdm
```
