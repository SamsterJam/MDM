# MDM - Minimal Display Manager

A minimal display manager with a clean TUI, inspired by ly and sddm.

**Zero dependencies** - no external binaries or libraries needed (except PAM for authentication).

## Features

- Auto-detects system users (UID >= 1000)
- Auto-detects available sessions from `/usr/share/xsessions` and `/usr/share/wayland-sessions`
- Remembers last selected user and session
- PAM authentication
- Session management with privilege separation
- Dynamic terminal-size-aware UI
- Elegant keyboard navigation
- Works with X11 and Wayland sessions

## Installation

```bash
make
sudo make install
sudo systemctl enable mdm
sudo systemctl start mdm
```

## Usage

MDM automatically detects all available users and sessions. No configuration file needed!

The UI starts with focus on the password field for quick login. The session selector appears centered below the password field.

### Navigation

- **Enter**: Submit password and login (when on password field)
- **Tab**: Switch between password field and session selector
- **Left/Right Arrow Keys**: Change session (when focused on session selector)
- **Ctrl+C**: Exit

Your last selected user and session are remembered in `/var/cache/mdm/state`.

## How It Works

### User Detection
MDM scans `/etc/passwd` for users with:
- UID >= 1000 (regular users)
- Valid login shells (excludes `/bin/false`, `/usr/sbin/nologin`, etc.)

### Session Detection
MDM reads `.desktop` files from:
- `/usr/share/xsessions/*.desktop` - X11 sessions
- `/usr/share/wayland-sessions/*.desktop` - Wayland sessions

If no sessions are found, it defaults to `startx`.

### State Persistence
Last selected user and session are saved to `/var/cache/mdm/state` and automatically restored on next login.

### Font Rendering
MDM includes a lightweight FIGlet font parser that reads the standard font file directly - no external `figlet` binary required!

## Files

- `mdm.c` - Main source
- `ascii.c` / `ascii.h` - ASCII art font rendering engine
- `mdm.service` - Systemd service unit
- `pam.d/mdm` - PAM configuration
- `standard.flf` - FIGlet font file
- `Makefile` - Build and installation

## Troubleshooting

**Authentication failed:**
- Check `/etc/pam.d/mdm` is installed
- Check journal: `journalctl -u mdm -f`

**No users detected:**
- Ensure your user has UID >= 1000
- Check shell is valid: `getent passwd $USER`

**X/Wayland session fails:**
- For X11: Ensure `~/.xinitrc` exists
- Check session is installed: `ls /usr/share/xsessions/`
- Check session command exists: `which startx` / `which sway` / etc.

**Can't see UI:**
- Switch to TTY1: `Ctrl+Alt+F1`
- Check status: `systemctl status mdm`

**Disable other display managers:**
```bash
sudo systemctl disable gdm
sudo systemctl disable sddm
sudo systemctl disable lightdm
```
