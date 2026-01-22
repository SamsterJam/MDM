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
 * Update terminal size (called by SIGWINCH handler)
 */
void tui_update_size(void);

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
 *    0: Retry (empty password entered)
 *   -1: Exit/Ctrl-C pressed
 *   -2: Power action executed (suspend/shutdown/reboot)
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
