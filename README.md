# TermDM - Minimal Terminal Display Manager

A minimal, elegant display manager that demonstrates how authentication and session management work in Linux.

## Features

- **PAM Authentication** - Properly authenticates users against the system
- **Session Management** - Sets up proper login sessions with environment variables
- **Privilege Separation** - Drops root privileges before starting user sessions
- **Beautiful TUI** - Minimal, elegant terminal interface
- **Flexible** - Works with X11 (startx) or Wayland (sway, Hyprland, etc.)

## How It Works

### 1. PAM (Pluggable Authentication Modules)

PAM is the standard Linux authentication framework. When you type your password, here's what happens:

```c
pam_start()         // Initialize PAM with our service name "termdm"
pam_authenticate()  // Verify password against /etc/shadow
pam_acct_mgmt()     // Check if account is valid (not expired, etc.)
pam_open_session()  // Open a login session
// ... user's session runs ...
pam_close_session() // Clean up session
pam_end()           // Cleanup PAM
```

The PAM configuration at `/etc/pam.d/termdm` tells PAM which modules to use:
- `pam_unix.so` - Traditional Unix password authentication
- `pam_systemd.so` - Registers session with systemd-logind

### 2. Session Setup

Before starting the user's session, we must:

```c
// 1. Initialize supplementary groups
initgroups(username, gid);

// 2. Set group ID
setgid(gid);

// 3. Set user ID (must be last - can't change after this!)
setuid(uid);

// 4. Set environment variables
setenv("HOME", "/home/user", 1);
setenv("USER", "username", 1);
// ... etc

// 5. Change to user's home directory
chdir(pw->pw_dir);

// 6. Execute session command
execvp("startx", ...);
```

The order is critical! Once you call `setuid()`, you've dropped root privileges and can't get them back.

### 3. Why You Can't Use `su` or `sudo`

Your original shell script used:
```bash
echo $password | sudo -S -u $username startx
```

This doesn't work because:
- `sudo` doesn't set up a proper login session
- Environment variables aren't properly initialized
- X server needs specific permissions that sudo doesn't grant
- No PAM session is created, so systemd doesn't know about the login
- When the user logs out, cleanup doesn't happen

### 4. Process Tree

```
systemd
  └── termdm (runs as root on TTY7)
       └── [after successful login] user session (runs as user)
            └── startx / sway / etc.
                 └── window manager
                      └── applications
```

## Installation

```bash
# Build
make

# Install (requires root)
sudo make install

# Edit configuration
sudo nano /etc/termdm/config

# Enable and start
sudo systemctl enable termdm
sudo systemctl start termdm
```

## Configuration

Edit `/etc/termdm/config`:

```ini
# Username to authenticate
username=samsterjam

# Session command (executed after login)
session=startx
```

### Session Examples

```ini
# X11 with default ~/.xinitrc
session=startx

# Sway (Wayland)
session=sway

# Hyprland
session=Hyprland

# i3 specifically
session=startx /usr/bin/i3

# GNOME
session=gnome-session

# KDE Plasma
session=startplasma-x11
```

## How to Customize the ASCII Art

The ASCII art is hardcoded in `termdm.c` at line 120. To change it:

1. Generate ASCII art:
   ```bash
   figlet -f standard "Your Name" > art.txt
   ```

2. Edit `termdm.c` and replace the `ascii_lines[]` array with your text

3. Rebuild:
   ```bash
   make clean && make
   sudo make install
   ```

## Files

- `termdm.c` - Main source code with extensive comments
- `termdm.service` - Systemd service unit
- `pam.d/termdm` - PAM configuration
- `config.example` - Example configuration file
- `Makefile` - Build and installation

## Differences from ly/SDDM/GDM

**TermDM:**
- Single user (configured in config file)
- No user selection UI
- ~500 lines of C
- Educational focus

**ly:**
- Multi-user selection
- Multiple session types per user
- More features (language selection, etc.)
- ~2000+ lines

**SDDM/GDM:**
- Graphical (Qt/GTK)
- Themes, customization
- Multi-seat support
- 10,000+ lines

## Security Notes

This is a minimal display manager for educational purposes and personal use. It:

- Authenticates properly via PAM
- Clears passwords from memory
- Drops privileges correctly
- Sets up proper sessions

However, it doesn't have:
- Rate limiting on failed logins
- Audit logging
- SELinux/AppArmor integration
- Multi-seat support

For production use on a multi-user system, consider ly, SDDM, or GDM.

## Troubleshooting

**"Authentication failed" even with correct password:**
- Check `/etc/pam.d/termdm` is installed
- Check journal: `journalctl -u termdm -f`
- Try manually: `sudo /usr/local/bin/termdm`

**X server fails to start:**
- Ensure you have a `~/.xinitrc` file
- Check X is installed: `which startx`
- Try running `startx` manually first

**Can't see the UI:**
- Switch to TTY7: Press `Ctrl+Alt+F7`
- Check service status: `systemctl status termdm`

**systemd conflicts:**
- Disable other display managers:
  ```bash
  sudo systemctl disable gdm
  sudo systemctl disable sddm
  sudo systemctl disable lightdm
  ```

## Learning More

Key concepts to understand:

1. **PAM** - Read `/etc/pam.d/login` to see how the login program uses PAM
2. **setuid/setgid** - `man 2 setuid`, understand privilege separation
3. **fork/exec** - `man 2 fork`, `man 2 execve`, process creation
4. **TTYs** - Virtual terminals, `/dev/tty1` through `/dev/tty7`
5. **systemd-logind** - Session management, `loginctl` command

## License

Public Domain - do whatever you want with it!
