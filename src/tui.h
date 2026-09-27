/*
 * TUI - Terminal User Interface for MDM
 * Handles all terminal display and input logic
 */

#ifndef TUI_H
#define TUI_H

#include "types.h"
#include "config.h"

/*
 * Initialize the TUI subsystem
 * - Detects terminal size
 * - Should be called once at startup
 */
void tui_init(void);

/*
 * Flag a terminal resize (async-signal-safe, called from the SIGWINCH handler)
 */
void tui_notify_resize(void);

/*
 * Put the login TTY in raw mode (no echo, no canonical line editing) and keep
 * it there. Must be held for as long as MDM owns the screen - in cooked mode
 * the kernel echoes keystrokes onto the login box in plaintext and queues them
 * for the next password read.
 *
 * Safe to call repeatedly; each call also flushes pending input, so anything
 * typed while the terminal was echoing is discarded rather than reused.
 *
 * Returns 0 if echo is confirmed off, -1 otherwise. A -1 must be treated as
 * "do not prompt for a password".
 */
int tui_enter_raw(void);

/*
 * Restore the terminal mode saved by the first tui_enter_raw(). Call only when
 * MDM is handing the TTY to a session or exiting - never while the login
 * screen is still displayed.
 */
void tui_leave_raw(void);

/*
 * Display the login screen and handle user input
 *
 * Parameters:
 *   username       - IN/OUT: username to display and allow editing
 *   password       - OUT: buffer to store entered password
 *   users          - IN: array of available users
 *   user_count     - IN: number of users in array
 *   sessions       - IN: array of available sessions
 *   session_count  - IN: number of sessions in array
 *   current_user   - IN/OUT: pointer to current user index
 *   current_session - IN/OUT: pointer to current session index
 *   colors         - IN: pointer to color configuration
 *
 * Returns:
 *    1: Success, user entered password (proceed with authentication)
 *    0: Redraw and call again (empty password, resize, or power action)
 *   -1: Exit/Ctrl-C pressed
 *
 * The TTY is left in raw mode on every path; the caller keeps it that way
 * until it hands the terminal to a session or exits.
 */
int tui_display_login(
    char *username,
    char *password,
    User *users,
    int user_count,
    Session *sessions,
    int session_count,
    int *current_user,
    int *current_session,
    ColorConfig *colors
);

/*
 * Display a centered message on the screen
 *
 * Parameters:
 *   message - The message to display
 *   color   - ANSI color code for the message (can be NULL for default)
 */
void tui_show_message(const char *message, const char *color);

#endif /* TUI_H */
