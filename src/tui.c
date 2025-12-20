/*
 * TUI - Terminal User Interface for MDM
 * Handles all terminal display and input logic
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include "types.h"
#include "tui.h"
#include "figlet.h"
#include "config.h"

#define MAX_PASSWORD 256
#define FONT_FILE "/usr/share/mdm/standard.flf"
#define FONT_FILE_SMALL "/usr/share/mdm/small.flf"
#define FONT_FILE_MINI "/usr/share/mdm/mini.flf"

/* Box layout constants */
#define BOX_WIDTH 70
#define BOX_HEIGHT 13
#define BOX_PADDING 3
#define TITLE_OFFSET 6
#define INPUT_OFFSET 10
#define SESSION_OFFSET 4

/* Terminal dimensions - managed by TUI module */
static int term_rows = 24;
static int term_cols = 80;

static void get_term_size(void) {
    struct winsize ws;
    static int first_call = 1;
    int retries = first_call ? 10 : 1;  // Only retry on first call

    // Retry getting terminal size with small delays
    // This handles the case where TTY isn't fully initialized on first boot
    while (retries > 0) {
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
            // Check if we got valid dimensions (not 0x0, too small, or unreasonably large)
            if (ws.ws_row > 10 && ws.ws_col > 40 && ws.ws_row < 512 && ws.ws_col < 512) {
                term_rows = ws.ws_row;
                term_cols = ws.ws_col;
                first_call = 0;
                return;
            }
        }

        // Small delay before retry (10ms) - only on first call
        if (first_call) {
            usleep(10000);
        }
        retries--;
    }

    // Fallback to environment variables if ioctl keeps failing (first call only)
    if (first_call) {
        char *lines = getenv("LINES");
        char *cols = getenv("COLUMNS");
        if (lines) term_rows = atoi(lines);
        if (cols) term_cols = atoi(cols);

        // Final fallback to standard VT100 dimensions
        if (term_rows == 0) term_rows = 24;
        if (term_cols == 0) term_cols = 80;
    }

    first_call = 0;
}

static void draw_repeat(const char *str, int count) {
    for (int i = 0; i < count; i++)
        printf("%s", str);
}

static void draw_box(int row, int col, int width, int height) {
    printf("\033[%d;%dH┌", row, col);
    draw_repeat("─", width);
    printf("┐");

    for (int i = 1; i <= height; i++) {
        printf("\033[%d;%dH│", row + i, col);
        printf("\033[%d;%dH│", row + i, col + width + 1);
    }

    printf("\033[%d;%dH└", row + height + 1, col);
    draw_repeat("─", width);
    printf("┘");
}

static int get_max_line_width(char **lines, int line_count) {
    int max_width = 0;
    for (int i = 0; i < line_count; i++) {
        int len = strlen(lines[i]);
        if (len > max_width) {
            max_width = len;
        }
    }
    return max_width;
}

static void draw_title(int start_row, int start_col, int box_width, const char *username, int highlighted) {
    static char line_buffers[32][512];
    char *lines[32];
    int line_count;
    int max_width;
    int use_plain_text = 0;

    // Cache the last successful font choice based on username length
    static int cached_len = 0;
    static const char *cached_font = NULL;
    int username_len = strlen(username);

    // Initialize line pointers
    for (int i = 0; i < 32; i++) {
        lines[i] = line_buffers[i];
        line_buffers[i][0] = '\0';
    }

    // Only use cached font if username is same length or longer
    // (if shorter, we should try bigger fonts first)
    if (cached_font != NULL && username_len >= cached_len) {
        if (strcmp(cached_font, FONT_FILE) != 0) {
            figlet_init(cached_font);
        }
        line_count = figlet_render(username, lines, 32);
        if (line_count > 0) {
            max_width = get_max_line_width(lines, line_count);
            if (max_width < box_width) {
                goto render_success;  // Cache hit, use this font
            }
        }
        // Cache miss, fall through to try all fonts
        figlet_init(FONT_FILE);  // Reset to standard
    } else {
        // No cache or username got shorter, reset to standard font
        figlet_init(FONT_FILE);
    }

    // Try rendering with standard font
    line_count = figlet_render(username, lines, 32);

    if (line_count > 0) {
        max_width = get_max_line_width(lines, line_count);

        if (max_width < box_width) {
            cached_font = FONT_FILE;
            cached_len = username_len;
            goto render_success;
        }

        // If too wide, try small font
        if (figlet_init(FONT_FILE_SMALL) == 0) {
            for (int i = 0; i < 32; i++) {
                line_buffers[i][0] = '\0';
            }
            line_count = figlet_render(username, lines, 32);
            if (line_count > 0) {
                max_width = get_max_line_width(lines, line_count);
                if (max_width < box_width) {
                    cached_font = FONT_FILE_SMALL;
                    cached_len = username_len;
                    goto render_success;
                }
            }
        }

        // If still too wide, try mini font
        if (figlet_init(FONT_FILE_MINI) == 0) {
            for (int i = 0; i < 32; i++) {
                line_buffers[i][0] = '\0';
            }
            line_count = figlet_render(username, lines, 32);
            if (line_count > 0) {
                max_width = get_max_line_width(lines, line_count);
                if (max_width < box_width) {
                    cached_font = FONT_FILE_MINI;
                    cached_len = username_len;
                    goto render_success;
                }
            }
        }

        // If still too wide, fall back to plain text
        use_plain_text = 1;
        cached_font = NULL;  // Clear cache for plain text
    } else {
        use_plain_text = 1;
        cached_font = NULL;
    }

render_success:

    const char *color_start = highlighted ?
        config_get_ansi_color("ascii_highlight") :
        config_get_ansi_color("ascii_art");

    if (use_plain_text) {
        // Render as plain text centered in the box
        int len = strlen(username);
        int col = start_col + (box_width - len) / 2 + 1;
        if (col < start_col + 1) col = start_col + 1;
        printf("\033[%d;%dH%s%s\033[0m", start_row + 5, col, color_start, username);
    } else {
        // Render the ASCII art
        for (int i = 0; i < line_count; i++) {
            int len = strlen(lines[i]);
            int col = start_col + (box_width - len) / 2 + 1;
            if (col < start_col + 1) col = start_col + 1;
            printf("\033[%d;%dH%s%s\033[0m", start_row + i + 3, col, color_start, lines[i]);
        }
    }

    // Only reload standard font if we're not using it (for consistency)
    // The cache will handle font selection on next call
    if (!use_plain_text && cached_font != NULL && strcmp(cached_font, FONT_FILE) != 0) {
        figlet_init(cached_font);  // Keep the cached font loaded
    }
}

static void draw_session_selector(int row, int col, Session *sessions, int current_session, int is_active) {
    char display[256];
    int len;

    if (is_active) {
        snprintf(display, sizeof(display), "%s<%s %s%s%s %s>%s",
                config_get_ansi_color("selector"),
                "\033[0m",
                config_get_ansi_color("session"),
                sessions[current_session].name,
                "\033[0m",
                config_get_ansi_color("selector"),
                "\033[0m");
    } else {
        snprintf(display, sizeof(display), "%s  %s  \033[0m",
                config_get_ansi_color("session_dim"),
                sessions[current_session].name);
    }

    len = strlen(sessions[current_session].name) + 4;
    int start_col = col - len / 2;
    printf("\033[%d;%dH%s", row, start_col, display);
}

static void draw_password(int row, int col, int pass_pos) {
    printf("\033[%d;%dH", row, col);
    for (int i = 0; i < pass_pos; i++) {
        putchar('*');
    }
    fflush(stdout);
}

static void draw_power_hotkeys(ColorConfig *colors) {
    if (!colors->show_power_hotkeys) {
        return;
    }

    const char *color = config_get_ansi_color("power_hotkeys");
    char suspend_hint[32], shutdown_hint[32], reboot_hint[32];

    snprintf(suspend_hint, sizeof(suspend_hint), "%s to Suspend", colors->suspend_hotkey);
    snprintf(shutdown_hint, sizeof(shutdown_hint), "%s to Shutdown", colors->shutdown_hotkey);
    snprintf(reboot_hint, sizeof(reboot_hint), "%s to Reboot", colors->reboot_hotkey);

    int bottom_row = term_rows - 1;

    // Left: Suspend
    printf("\033[%d;2H%s%s\033[0m", bottom_row, color, suspend_hint);

    // Center: Shutdown
    int shutdown_len = strlen(shutdown_hint);
    int center_col = (term_cols - shutdown_len) / 2;
    printf("\033[%d;%dH%s%s\033[0m", bottom_row, center_col, color, shutdown_hint);

    // Right: Reboot
    int reboot_len = strlen(reboot_hint);
    int right_col = term_cols - reboot_len - 1;
    printf("\033[%d;%dH%s%s\033[0m", bottom_row, right_col, color, reboot_hint);

    fflush(stdout);
}

static void redraw_login_screen(int start_row, int start_col, int input_row, int input_col, int input_width,
                                int pass_row, int pass_col, int pass_pos, int session_row, int center_col,
                                const char *username, int username_highlighted,
                                Session *sessions, int current_session, int session_active,
                                ColorConfig *colors) {
    printf("\033[2J\033[H\033[?25l");
    draw_box(start_row, start_col, BOX_WIDTH, BOX_HEIGHT);
    draw_title(start_row, start_col, BOX_WIDTH, username, username_highlighted);
    draw_box(input_row, input_col, input_width, 1);
    draw_password(pass_row, pass_col, pass_pos);
    draw_session_selector(session_row, center_col, sessions, current_session, session_active);
    draw_power_hotkeys(colors);
}

static int get_function_key_num(const char *hotkey) {
    if (!hotkey || (hotkey[0] != 'F' && hotkey[0] != 'f'))
        return 0;
    int key_num = atoi(hotkey + 1);
    return (key_num >= 1 && key_num <= 12) ? key_num : 0;
}

static int check_hotkey_match(char bracket_code, char seq_c1, char seq_c2, char tilde, int target_key) {
    if (!target_key) return 0;

    // F1-F5: ESC [ [ A-E
    if (bracket_code && target_key >= 1 && target_key <= 5) {
        return bracket_code == ('A' + target_key - 1);
    }

    // F6-F12: ESC [ XY~
    if (tilde == '~' && target_key >= 6 && target_key <= 12) {
        const char *seqs[] = {"", "", "", "", "", "17", "18", "19", "20", "21", "23", "24"};
        return (seq_c1 == seqs[target_key - 1][0] && seq_c2 == seqs[target_key - 1][1]);
    }

    return 0;
}

static int handle_power_action(struct termios *old, const char *action, const char *cmd) {
    tcsetattr(STDIN_FILENO, TCSANOW, old);
    printf("\033[2J\033[H");
    int msg_len = strlen(action);
    printf("\033[%d;%dH%s%s\033[0m\n", term_rows / 2, (term_cols - msg_len) / 2,
           config_get_ansi_color("info"), action);
    fflush(stdout);
    system(cmd);
    printf("\033[?25l");
    return -2;
}

static int handle_input(char *username, char *password, int max_len, int *pass_pos, int *user_pos,
                       int *active_field, int *user_edit_mode, int user_row, int pass_row,
                       int pass_col, int session_row, int center_col,
                       int start_row, int start_col, int input_col, int input_width,
                       Session *sessions, int session_count, int *current_session, ColorConfig *colors) {
    struct termios old, new;
    char original_username[MAX_NAME];

    tcgetattr(STDIN_FILENO, &old);
    new = old;
    new.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSANOW, &new);

    snprintf(original_username, MAX_NAME, "%s", username);

    while (1) {
        if (*active_field == 0 && *user_edit_mode) {
            int edit_col = center_col - (int)(strlen(username) / 2) + *user_pos;
            printf("\033[?25h\033[%d;%dH", user_row, edit_col);
        } else if (*active_field == 1) {
            printf("\033[?25h\033[%d;%dH", pass_row, pass_col + *pass_pos);
        } else {
            printf("\033[?25l");
        }
        fflush(stdout);

        int c = getchar();

        if (c == 3) {
            tcsetattr(STDIN_FILENO, TCSANOW, &old);
            printf("\033[?25l");
            return -1;
        }

        if (c == '\t') {
            if (*active_field == 0 && *user_edit_mode) {
                *user_edit_mode = 0;
                redraw_login_screen(start_row, start_col, pass_row - 1, input_col, input_width,
                                  pass_row, pass_col, *pass_pos, session_row, center_col,
                                  username, 0, sessions, *current_session, 0, colors);
            }
            int old_field = *active_field;
            *active_field = (*active_field + 1) % 3;
            if (old_field == 0 && !*user_edit_mode) {
                redraw_login_screen(start_row, start_col, pass_row - 1, input_col, input_width,
                                  pass_row, pass_col, *pass_pos, session_row, center_col,
                                  username, 0, sessions, *current_session, 0, colors);
            } else if (*active_field == 0 && !*user_edit_mode) {
                redraw_login_screen(start_row, start_col, pass_row - 1, input_col, input_width,
                                  pass_row, pass_col, *pass_pos, session_row, center_col,
                                  username, 1, sessions, *current_session, 0, colors);
            }
            draw_session_selector(session_row, center_col, sessions, *current_session, *active_field == 2);
            fflush(stdout);
            continue;
        }

        if (c == 27) {
            c = getchar();
            if (c == '[') {
                c = getchar();

                int suspend_key = get_function_key_num(colors->suspend_hotkey);
                int shutdown_key = get_function_key_num(colors->shutdown_hotkey);
                int reboot_key = get_function_key_num(colors->reboot_hotkey);

                // Handle F1-F5: ESC [ [ X
                if (c == '[') {
                    char code = getchar();
                    if (check_hotkey_match(code, 0, 0, 0, suspend_key))
                        return handle_power_action(&old, "Suspending...", "systemctl suspend");
                    if (check_hotkey_match(code, 0, 0, 0, shutdown_key))
                        return handle_power_action(&old, "Shutting down...", "systemctl poweroff");
                    if (check_hotkey_match(code, 0, 0, 0, reboot_key))
                        return handle_power_action(&old, "Rebooting...", "systemctl reboot");
                    continue;
                }

                // Handle F6-F12: ESC [ XY~
                if (c >= '1' && c <= '2') {
                    char c1 = c, c2 = getchar();
                    if (c2 >= '0' && c2 <= '9') {
                        char tilde = getchar();
                        if (check_hotkey_match(0, c1, c2, tilde, suspend_key))
                            return handle_power_action(&old, "Suspending...", "systemctl suspend");
                        if (check_hotkey_match(0, c1, c2, tilde, shutdown_key))
                            return handle_power_action(&old, "Shutting down...", "systemctl poweroff");
                        if (check_hotkey_match(0, c1, c2, tilde, reboot_key))
                            return handle_power_action(&old, "Rebooting...", "systemctl reboot");
                    }
                    continue;
                }

                // Handle arrow keys for session selection
                if (*active_field == 2 && (c == 'D' || c == 'C')) {
                    *current_session = (c == 'D') ?
                        (*current_session + session_count - 1) % session_count :
                        (*current_session + 1) % session_count;
                    int clear_start = center_col - 25;
                    printf("\033[%d;%dH", session_row, clear_start);
                    for (int i = 0; i < 50; i++) printf("─");
                    draw_session_selector(session_row, center_col, sessions, *current_session, 1);
                    fflush(stdout);
                }
            }
            continue;
        }

        if (*active_field == 0) {
            if (*user_edit_mode) {
                if (c == '\n' || c == '\r') {
                    if (strlen(username) == 0) {
                        snprintf(username, MAX_NAME, "%s", original_username);
                        *user_pos = strlen(username);
                    } else {
                        snprintf(original_username, MAX_NAME, "%s", username);
                    }
                    *user_edit_mode = 0;
                    redraw_login_screen(start_row, start_col, pass_row - 1, input_col, input_width,
                                      pass_row, pass_col, *pass_pos, session_row, center_col,
                                      username, 1, sessions, *current_session, 0, colors);
                    fflush(stdout);
                } else if (c == 127 || c == 8) {
                    if (*user_pos > 0) {
                        (*user_pos)--;
                        username[*user_pos] = '\0';
                        printf("\033[%d;%dH%-70s", user_row, start_col + 1, "");
                        int text_col = center_col - (int)(strlen(username) / 2);
                        printf("\033[%d;%dH%s", user_row, text_col, username);
                        fflush(stdout);
                    }
                } else if (*user_pos < MAX_NAME - 1 && c >= 32 && c < 127) {
                    username[(*user_pos)++] = c;
                    username[*user_pos] = '\0';
                    printf("\033[%d;%dH%-70s", user_row, start_col + 1, "");
                    int text_col = center_col - (int)(strlen(username) / 2);
                    printf("\033[%d;%dH%s", user_row, text_col, username);
                    fflush(stdout);
                }
            } else {
                if (c == '\n' || c == '\r') {
                    *user_edit_mode = 1;
                    *user_pos = strlen(username);
                    for (int i = 0; i < 6; i++) {
                        printf("\033[%d;%dH%-70s", start_row + i + 3, start_col + 1, "");
                    }
                    int text_col = center_col - (int)(strlen(username) / 2);
                    printf("\033[%d;%dH%s", user_row, text_col, username);
                    fflush(stdout);
                }
            }
        } else if (*active_field == 1) {
            if (c == '\n' || c == '\r') {
                password[*pass_pos] = '\0';
                break;
            } else if (c == 127 || c == 8) {
                if (*pass_pos > 0) {
                    (*pass_pos)--;
                    printf("\b \b");
                    fflush(stdout);
                }
            } else if (*pass_pos < max_len - 1 && c >= 32 && c < 127) {
                password[(*pass_pos)++] = c;
                putchar('*');
                fflush(stdout);
            }
        } else if (*active_field == 2) {
            if (c == '\n' || c == '\r') {
                *active_field = 1;
                draw_session_selector(session_row, center_col, sessions, *current_session, 0);
                fflush(stdout);
            }
        }
    }

    printf("\033[?25l");
    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    return 0;
}

/* Public API implementations */

void tui_init(void) {
    get_term_size();
}

void tui_show_message(const char *message, const char *color) {
    printf("\033[2J\033[H");

    int msg_len = strlen(message);
    int row = term_rows / 2;
    int col = (term_cols - msg_len) / 2;

    if (col < 1) col = 1;
    if (row < 1) row = 1;

    if (color) {
        printf("\033[%d;%dH%s%s\033[0m", row, col, color, message);
    } else {
        printf("\033[%d;%dH%s", row, col, message);
    }

    fflush(stdout);
}

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
) {
    (void)users;       // Unused for now
    (void)user_count;  // Unused for now
    (void)current_user; // Unused for now

    int start_col = (term_cols - BOX_WIDTH - 2) / 2;
    int start_row = (term_rows - BOX_HEIGHT - 2) / 2;

    if (start_col < 1) start_col = 1;
    if (start_row < 1) start_row = 1;

    printf("\033[2J\033[H\033[?25l");

    draw_box(start_row, start_col, BOX_WIDTH, BOX_HEIGHT);
    draw_title(start_row, start_col, BOX_WIDTH, username, 0);

    int user_row = start_row + TITLE_OFFSET;
    int center_col = start_col + BOX_WIDTH / 2 + 1;

    int input_row = start_row + INPUT_OFFSET;
    int input_col = start_col + BOX_PADDING;
    int input_width = BOX_WIDTH - (BOX_PADDING * 2);

    draw_box(input_row, input_col, input_width, 1);

    int field_row = input_row + 1;
    int field_col = input_col + 2;

    int session_row = input_row + SESSION_OFFSET;

    draw_session_selector(session_row, center_col, sessions, *current_session, 0);
    draw_power_hotkeys(colors);

    int active_field = 1;
    int pass_pos = 0;
    int user_pos = strlen(username);
    int user_edit_mode = 0;

    int result = handle_input(username, password, MAX_PASSWORD, &pass_pos, &user_pos, &active_field,
                    &user_edit_mode, user_row, field_row, field_col, session_row, center_col,
                    start_row, start_col, input_col, input_width, sessions, session_count, current_session, colors);

    if (result < 0)
        return result;

    if (strlen(password) == 0) {
        printf("\033[%d;%dH%sPassword cannot be empty\033[0m", input_row + 2, input_col + 2,
               config_get_ansi_color("error"));
        fflush(stdout);
        sleep(1);
        return 0;
    }

    return 1;
}
