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
#include <sys/select.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include "types.h"
#include "tui.h"
#include "figlet.h"
#include "config.h"
#include "log.h"

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

/* Internal return codes */
#define RETURN_RESIZE -3  // Terminal was resized, trigger redraw

static int term_rows = 24;
static int term_cols = 80;
static volatile sig_atomic_t term_resized = 0;

static void get_term_size(void) {
    struct winsize ws;

    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0 && ws.ws_col > 0) {
        term_rows = ws.ws_row;
        term_cols = ws.ws_col;
        log_debugf("Terminal size: %dx%d", term_rows, term_cols);
    } else {
        term_rows = 24;
        term_cols = 80;
        log_warnf("Using default terminal size: %dx%d", term_rows, term_cols);
    }
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

/* Track the currently-loaded figlet font so redraws don't re-read it from disk */
static const char *loaded_font = NULL;

static int ensure_font(const char *font_path) {
    if (loaded_font && strcmp(loaded_font, font_path) == 0)
        return 0;
    loaded_font = NULL;  // figlet_init unloads the current font even on failure
    if (figlet_init(font_path) != 0)
        return -1;
    loaded_font = font_path;
    return 0;
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

    for (int i = 0; i < 32; i++) {
        lines[i] = line_buffers[i];
        line_buffers[i][0] = '\0';
    }

    // A shorter username may fit a bigger font, so only trust the cache
    // when the username is the same length or longer
    if (cached_font != NULL && username_len >= cached_len) {
        ensure_font(cached_font);
        line_count = figlet_render(username, lines, 32);
        if (line_count > 0) {
            max_width = get_max_line_width(lines, line_count);
            if (max_width < box_width) {
                goto render_success;
            }
        }
        ensure_font(FONT_FILE);
    } else {
        ensure_font(FONT_FILE);
    }

    line_count = figlet_render(username, lines, 32);

    if (line_count > 0) {
        max_width = get_max_line_width(lines, line_count);

        if (max_width < box_width) {
            cached_font = FONT_FILE;
            cached_len = username_len;
            goto render_success;
        }

        // Too wide: try progressively smaller fonts
        if (ensure_font(FONT_FILE_SMALL) == 0) {
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

        if (ensure_font(FONT_FILE_MINI) == 0) {
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

        use_plain_text = 1;
        cached_font = NULL;
    } else {
        use_plain_text = 1;
        cached_font = NULL;
    }

render_success:;

    const char *color_start = highlighted ?
        config_get_ansi_color("ascii_highlight") :
        config_get_ansi_color("ascii_art");

    if (use_plain_text) {
        int len = strlen(username);
        int col = start_col + (box_width - len) / 2 + 1;
        if (col < start_col + 1) col = start_col + 1;
        printf("\033[%d;%dH%s%s\033[0m", start_row + 5, col, color_start, username);
    } else {
        for (int i = 0; i < line_count; i++) {
            int len = strlen(lines[i]);
            int col = start_col + (box_width - len) / 2 + 1;
            if (col < start_col + 1) col = start_col + 1;
            printf("\033[%d;%dH%s%s\033[0m", start_row + i + 3, col, color_start, lines[i]);
        }
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

    printf("\033[%d;2H%s%s\033[0m", bottom_row, color, suspend_hint);

    int shutdown_len = strlen(shutdown_hint);
    int center_col = (term_cols - shutdown_len) / 2;
    printf("\033[%d;%dH%s%s\033[0m", bottom_row, center_col, color, shutdown_hint);

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

/*
 * Read one byte with a timeout, or -1 - so a bare ESC press doesn't
 * block mid-sequence and swallow the next keystroke.
 */
static int read_byte_timeout(int timeout_ms) {
    fd_set fds;
    struct timeval tv;
    unsigned char b;

    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    if (select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) != 1)
        return -1;
    if (read(STDIN_FILENO, &b, 1) != 1)
        return -1;
    return b;
}

/* Map "ESC [ <num> ~" sequences to function key numbers */
static int fkey_from_tilde_num(int num) {
    switch (num) {
        case 17: return 6;
        case 18: return 7;
        case 19: return 8;
        case 20: return 9;
        case 21: return 10;
        case 23: return 11;
        case 24: return 12;
        default: return 0;
    }
}

static int handle_power_action(struct termios *old, const char *action, const char *verb) {
    tcsetattr(STDIN_FILENO, TCSANOW, old);
    printf("\033[2J\033[H");
    int msg_len = strlen(action);
    printf("\033[%d;%dH%s%s\033[0m\n", term_rows / 2, (term_cols - msg_len) / 2,
           config_get_ansi_color("info"), action);
    fflush(stdout);

    // Runs as root: fixed path, no shell
    pid_t pid = fork();
    if (pid == 0) {
        execl("/usr/bin/systemctl", "systemctl", verb, (char *)NULL);
        _exit(127);
    }
    if (pid > 0) {
        int status;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
            ;
    }

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
    // No ISIG/IXON: Ctrl+C/Z/S must not kill, suspend, or freeze the DM
    new.c_lflag &= ~(ECHO | ICANON | ISIG);
    new.c_iflag &= ~IXON;
    tcsetattr(STDIN_FILENO, TCSANOW, &new);

    snprintf(original_username, MAX_NAME, "%s", username);

    while (1) {
        if (term_resized) {
            term_resized = 0;
            get_term_size();  // Not done in the signal handler; ioctl+log here
            tcsetattr(STDIN_FILENO, TCSANOW, &old);
            return RETURN_RESIZE;
        }

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

        // SIGWINCH interrupts getchar(); loop back to the resize check
        if (c == EOF && errno == EINTR) {
            clearerr(stdin);
            continue;
        }

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
            int b = read_byte_timeout(100);
            if (b != '[')
                continue;  // Bare ESC or unrecognized sequence

            int fkey = 0;
            b = read_byte_timeout(100);

            if (b == '[') {
                // Linux console F1-F5: ESC [ [ A-E
                int code = read_byte_timeout(100);
                if (code >= 'A' && code <= 'E')
                    fkey = code - 'A' + 1;
            } else {
                // Generic CSI: consume the whole sequence so stray bytes
                // (e.g. the '~' from Delete/PgUp) can't leak into the password
                int num = 0, have_num = 0;
                while (b >= '0' && b <= '9') {
                    num = num * 10 + (b - '0');
                    have_num = 1;
                    b = read_byte_timeout(100);
                }
                while (b == ';' || (b >= '0' && b <= '9'))
                    b = read_byte_timeout(100);  // Drain modifier parameters

                if (b == '~' && have_num) {
                    fkey = fkey_from_tilde_num(num);
                } else if (*active_field == 2 && (b == 'D' || b == 'C')) {
                    *current_session = (b == 'D') ?
                        (*current_session + session_count - 1) % session_count :
                        (*current_session + 1) % session_count;
                    int clear_start = center_col - 25;
                    printf("\033[%d;%dH", session_row, clear_start);
                    for (int i = 0; i < 50; i++) printf("─");
                    draw_session_selector(session_row, center_col, sessions, *current_session, 1);
                    fflush(stdout);
                }
            }

            if (fkey) {
                if (fkey == get_function_key_num(colors->suspend_hotkey))
                    return handle_power_action(&old, "Suspending...", "suspend");
                if (fkey == get_function_key_num(colors->shutdown_hotkey))
                    return handle_power_action(&old, "Shutting down...", "poweroff");
                if (fkey == get_function_key_num(colors->reboot_hotkey))
                    return handle_power_action(&old, "Rebooting...", "reboot");
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

void tui_notify_resize(void) {
    // Runs in signal context: must stay async-signal-safe
    term_resized = 1;
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

    if (result == RETURN_RESIZE) {
        return 0;  // Caller redraws with the new dimensions
    }

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
