/*
 * TermDM - A Minimal Terminal Display Manager
 *
 * This demonstrates how display managers work:
 * 1. Run as root
 * 2. Use PAM to authenticate users
 * 3. Fork and drop privileges to the user
 * 4. Start X/Wayland session
 * 5. Wait for session and cleanup
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <termios.h>
#include <signal.h>
#include <errno.h>

#define MAX_PASSWORD 256
#define CONFIG_FILE "/etc/termdm/config"

/* Terminal dimensions */
static int term_rows = 24;
static int term_cols = 80;

/* User configuration */
static char default_username[64] = "samsterjam";
static char session_cmd[256] = "startx";

/* PAM conversation function - handles password prompts */
static int pam_conversation(int num_msg, const struct pam_message **msg,
                            struct pam_response **resp, void *appdata_ptr) {
    struct pam_response *reply;
    char *password = (char *)appdata_ptr;

    if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG)
        return PAM_CONV_ERR;

    reply = calloc(num_msg, sizeof(struct pam_response));
    if (!reply)
        return PAM_BUF_ERR;

    for (int i = 0; i < num_msg; i++) {
        switch (msg[i]->msg_style) {
            case PAM_PROMPT_ECHO_OFF: /* Password prompt */
                reply[i].resp = strdup(password);
                reply[i].resp_retcode = 0;
                break;
            case PAM_PROMPT_ECHO_ON:
                reply[i].resp = NULL;
                reply[i].resp_retcode = 0;
                break;
            case PAM_ERROR_MSG:
            case PAM_TEXT_INFO:
                reply[i].resp = NULL;
                reply[i].resp_retcode = 0;
                break;
            default:
                free(reply);
                return PAM_CONV_ERR;
        }
    }

    *resp = reply;
    return PAM_SUCCESS;
}

/* Load configuration file */
static void load_config(void) {
    FILE *f = fopen(CONFIG_FILE, "r");
    if (!f) return;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = line;
        char *value = eq + 1;

        /* Trim newline */
        char *nl = strchr(value, '\n');
        if (nl) *nl = '\0';

        if (strcmp(key, "username") == 0)
            strncpy(default_username, value, sizeof(default_username) - 1);
        else if (strcmp(key, "session") == 0)
            strncpy(session_cmd, value, sizeof(session_cmd) - 1);
    }

    fclose(f);
}

/* Get terminal size */
static void get_term_size(void) {
    /* Fallback to env or defaults */
    char *lines = getenv("LINES");
    char *cols = getenv("COLUMNS");
    if (lines) term_rows = atoi(lines);
    if (cols) term_cols = atoi(cols);
    if (term_rows == 0) term_rows = 24;
    if (term_cols == 0) term_cols = 80;
}

/* Draw a horizontal line of UTF-8 box characters */
static void draw_repeat(const char *str, int count) {
    for (int i = 0; i < count; i++)
        printf("%s", str);
}

/* Draw the ASCII art title */
static void draw_title(int start_row, int start_col, int box_width) {
    const char *ascii_lines[] = {
        " _____                     _            ___                 ",
        "/  ___|                   | |          |_  |                ",
        "\\ `--.  __ _ _ __ ___  ___| |_ ___ _ __  | | __ _ _ __ ___  ",
        " `--. \\/ _` | '_ ` _ \\/ __| __/ _ \\ '__| | |/ _` | '_ ` _ \\ ",
        "/\\__/ / (_| | | | | | \\__ \\ ||  __/ |/\\__/ / (_| | | | | | |",
        "\\____/ \\__,_|_| |_| |_|___/\\__\\___|_|\\____/ \\__,_|_| |_| |_|"
    };

    for (int i = 0; i < 6; i++) {
        int len = strlen(ascii_lines[i]);
        int col = start_col + (box_width - len) / 2 + 1;
        printf("\033[%d;%dH\033[1m%s\033[0m", start_row + i + 3, col, ascii_lines[i]);
    }
}

/* Draw a box */
static void draw_box(int row, int col, int width, int height) {
    /* Top */
    printf("\033[%d;%dH┌", row, col);
    draw_repeat("─", width);
    printf("┐");

    /* Sides */
    for (int i = 1; i <= height; i++) {
        printf("\033[%d;%dH│", row + i, col);
        printf("\033[%d;%dH│", row + i, col + width + 1);
    }

    /* Bottom */
    printf("\033[%d;%dH└", row + height + 1, col);
    draw_repeat("─", width);
    printf("┘");
}

/* Read password with masking */
static int read_password(char *password, int max_len, int field_row, int field_col) {
    struct termios old, new;
    int pos = 0;

    /* Disable echo */
    tcgetattr(STDIN_FILENO, &old);
    new = old;
    new.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSANOW, &new);

    /* Show cursor */
    printf("\033[?25h");
    printf("\033[%d;%dH", field_row, field_col);
    fflush(stdout);

    while (1) {
        int c = getchar();

        if (c == '\n' || c == '\r') {
            password[pos] = '\0';
            break;
        } else if (c == 127 || c == 8) { /* Backspace */
            if (pos > 0) {
                pos--;
                printf("\b \b");
                fflush(stdout);
            }
        } else if (c == 3) { /* Ctrl+C */
            tcsetattr(STDIN_FILENO, TCSANOW, &old);
            printf("\033[?25l");
            return -1;
        } else if (pos < max_len - 1 && c >= 32 && c < 127) {
            password[pos++] = c;
            putchar('*');
            fflush(stdout);
        }
    }

    /* Hide cursor and restore */
    printf("\033[?25l");
    tcsetattr(STDIN_FILENO, TCSANOW, &old);

    return 0;
}

/* Display login screen and get password */
static int display_login(char *password) {
    int box_width = 70;
    int box_height = 13;
    int start_col = (term_cols - box_width - 2) / 2;
    int start_row = (term_rows - box_height - 2) / 2;

    /* Clear screen, hide cursor */
    printf("\033[2J\033[H\033[?25l");

    /* Draw main box */
    draw_box(start_row, start_col, box_width, box_height);

    /* Draw title */
    draw_title(start_row, start_col, box_width);

    /* Draw password input box */
    int input_row = start_row + 10;
    int input_col = start_col + 4;
    int input_width = box_width - 6;

    draw_box(input_row, input_col, input_width, 2);

    /* Read password */
    int field_row = input_row + 1;
    int field_col = input_col + 2;

    if (read_password(password, MAX_PASSWORD, field_row, field_col) < 0)
        return -1;

    if (strlen(password) == 0) {
        printf("\033[%d;%dH\033[31mPassword cannot be empty\033[0m", input_row + 3, input_col + 2);
        fflush(stdout);
        sleep(1);
        return 0; /* Retry */
    }

    return 1; /* Success */
}

/* Setup environment for user session */
static void setup_user_environment(struct passwd *pw) {
    char xauth_path[256];

    /* Set standard environment variables */
    setenv("HOME", pw->pw_dir, 1);
    setenv("SHELL", pw->pw_shell, 1);
    setenv("USER", pw->pw_name, 1);
    setenv("LOGNAME", pw->pw_name, 1);
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/bin", 1);
    setenv("PWD", pw->pw_dir, 1);

    /* X11 specific */
    setenv("DISPLAY", ":0", 1);
    snprintf(xauth_path, sizeof(xauth_path), "%s/.Xauthority", pw->pw_dir);
    setenv("XAUTHORITY", xauth_path, 1);

    /* XDG and systemd-logind session variables */
    setenv("XDG_SESSION_TYPE", "x11", 1);
    setenv("XDG_SESSION_CLASS", "user", 1);
    setenv("XDG_SEAT", "seat0", 1);
    setenv("XDG_VTNR", "1", 1);

    /* Change to user's home directory */
    if (chdir(pw->pw_dir) != 0) {
        chdir("/");
    }
}

/* Initialize user groups */
static int init_groups(struct passwd *pw) {
    if (initgroups(pw->pw_name, pw->pw_gid) != 0) {
        perror("initgroups");
        return -1;
    }

    if (setgid(pw->pw_gid) != 0) {
        perror("setgid");
        return -1;
    }

    if (setuid(pw->pw_uid) != 0) {
        perror("setuid");
        return -1;
    }

    return 0;
}

/* Start user session */
static int start_session(const char *username, pam_handle_t *pamh) {
    struct passwd *pw = getpwnam(username);
    if (!pw) {
        fprintf(stderr, "User %s not found\n", username);
        return -1;
    }

    pid_t pid = fork();

    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        /* Child process - will become the user's session */

        /* Open PAM session */
        if (pam_open_session(pamh, 0) != PAM_SUCCESS) {
            fprintf(stderr, "Failed to open PAM session\n");
            exit(1);
        }

        /* Setup environment */
        setup_user_environment(pw);

        /* Drop privileges to user */
        if (init_groups(pw) != 0) {
            exit(1);
        }

        /* Execute session command */
        /* Parse session_cmd to handle arguments */
        char *argv[64];
        int argc = 0;
        char *cmd_copy = strdup(session_cmd);
        char *token = strtok(cmd_copy, " ");

        while (token && argc < 63) {
            argv[argc++] = token;
            token = strtok(NULL, " ");
        }
        argv[argc] = NULL;

        /* For startx, append vt1 argument if not already specified */
        if (argc > 0 && strcmp(argv[0], "startx") == 0) {
            /* Check if -- is already in args */
            int has_server_args = 0;
            for (int i = 0; i < argc; i++) {
                if (strcmp(argv[i], "--") == 0) {
                    has_server_args = 1;
                    break;
                }
            }
            if (!has_server_args && argc < 62) {
                argv[argc++] = "--";
                argv[argc++] = "vt1";
                argv[argc] = NULL;
            }
        }

        /* Try to execute */
        execvp(argv[0], argv);

        /* If we get here, exec failed */
        fprintf(stderr, "Failed to execute %s: %s\n", argv[0], strerror(errno));
        exit(1);
    }

    /* Parent process - wait for session to end */
    int status;
    waitpid(pid, &status, 0);

    /* Close PAM session */
    pam_close_session(pamh, 0);

    return 0;
}

/* Authenticate user with PAM */
static int authenticate(const char *username, const char *password) {
    pam_handle_t *pamh = NULL;
    struct pam_conv conv = {
        pam_conversation,
        (void *)password
    };

    int retval;

    /* Initialize PAM */
    retval = pam_start("termdm", username, &conv, &pamh);
    if (retval != PAM_SUCCESS) {
        fprintf(stderr, "pam_start failed: %s\n", pam_strerror(pamh, retval));
        return -1;
    }

    /* Authenticate */
    retval = pam_authenticate(pamh, 0);
    if (retval != PAM_SUCCESS) {
        fprintf(stderr, "Authentication failed: %s\n", pam_strerror(pamh, retval));
        pam_end(pamh, retval);
        return -1;
    }

    /* Check account validity */
    retval = pam_acct_mgmt(pamh, 0);
    if (retval != PAM_SUCCESS) {
        fprintf(stderr, "Account validation failed: %s\n", pam_strerror(pamh, retval));
        pam_end(pamh, retval);
        return -1;
    }

    /* Start session */
    start_session(username, pamh);

    /* Cleanup */
    pam_end(pamh, PAM_SUCCESS);

    return 0;
}

int main(void) {
    char password[MAX_PASSWORD];

    /* Must run as root */
    if (getuid() != 0) {
        fprintf(stderr, "termdm must be run as root\n");
        return 1;
    }

    /* Load config */
    load_config();

    /* Get terminal size */
    get_term_size();

    /* Main login loop */
    while (1) {
        memset(password, 0, sizeof(password));

        int result = display_login(password);

        if (result < 0) {
            /* User pressed Ctrl+C */
            printf("\033[2J\033[H\033[?25h");
            break;
        }

        if (result == 0) {
            /* Empty password, retry */
            continue;
        }

        /* Show "Authenticating..." message */
        printf("\033[2J\033[H");
        int msg_row = term_rows / 2;
        int msg_col = (term_cols - 20) / 2;
        printf("\033[%d;%dHAuthenticating...", msg_row, msg_col);
        fflush(stdout);

        /* Try to authenticate */
        if (authenticate(default_username, password) == 0) {
            /* Session ended, go back to login */
            memset(password, 0, sizeof(password));
            continue;
        } else {
            /* Authentication failed */
            printf("\033[2J\033[H");
            int err_row = term_rows / 2;
            int err_col = (term_cols - 25) / 2;
            printf("\033[%d;%dH\033[31mAuthentication failed!\033[0m", err_row, err_col);
            fflush(stdout);
            sleep(2);
            memset(password, 0, sizeof(password));
        }
    }

    /* Restore terminal */
    printf("\033[?25h\033[2J\033[H");

    return 0;
}
