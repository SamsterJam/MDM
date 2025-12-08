#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <termios.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#define MAX_PASSWORD 256
#define CONFIG_FILE "/etc/termdm/config"

static int term_rows = 24;
static int term_cols = 80;
static char default_username[64] = "samsterjam";
static char session_cmd[256] = "startx";

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
            case PAM_PROMPT_ECHO_OFF:
                reply[i].resp = strdup(password);
                reply[i].resp_retcode = 0;
                break;
            case PAM_PROMPT_ECHO_ON:
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

        char *nl = strchr(value, '\n');
        if (nl) *nl = '\0';

        if (strcmp(key, "username") == 0)
            strncpy(default_username, value, sizeof(default_username) - 1);
        else if (strcmp(key, "session") == 0)
            strncpy(session_cmd, value, sizeof(session_cmd) - 1);
    }

    fclose(f);
}

static void get_term_size(void) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        term_rows = ws.ws_row;
        term_cols = ws.ws_col;
    } else {
        char *lines = getenv("LINES");
        char *cols = getenv("COLUMNS");
        if (lines) term_rows = atoi(lines);
        if (cols) term_cols = atoi(cols);
    }
    if (term_rows == 0) term_rows = 24;
    if (term_cols == 0) term_cols = 80;
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

static int read_password(char *password, int max_len, int field_row, int field_col) {
    struct termios old, new;
    int pos = 0;

    tcgetattr(STDIN_FILENO, &old);
    new = old;
    new.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSANOW, &new);

    printf("\033[?25h");
    printf("\033[%d;%dH", field_row, field_col);
    fflush(stdout);

    while (1) {
        int c = getchar();

        if (c == '\n' || c == '\r') {
            password[pos] = '\0';
            break;
        } else if (c == 127 || c == 8) {
            if (pos > 0) {
                pos--;
                printf("\b \b");
                fflush(stdout);
            }
        } else if (c == 3) {
            tcsetattr(STDIN_FILENO, TCSANOW, &old);
            printf("\033[?25l");
            return -1;
        } else if (pos < max_len - 1 && c >= 32 && c < 127) {
            password[pos++] = c;
            putchar('*');
            fflush(stdout);
        }
    }

    printf("\033[?25l");
    tcsetattr(STDIN_FILENO, TCSANOW, &old);

    return 0;
}

static int display_login(char *password) {
    int box_width = 70;
    int box_height = 13;
    int start_col = (term_cols - box_width - 2) / 2;
    int start_row = (term_rows - box_height - 2) / 2;

    if (start_col < 1) start_col = 1;
    if (start_row < 1) start_row = 1;

    printf("\033[2J\033[H\033[?25l");

    draw_box(start_row, start_col, box_width, box_height);
    draw_title(start_row, start_col, box_width);

    int input_row = start_row + 10;
    int input_col = start_col + 4;
    int input_width = box_width - 6;

    draw_box(input_row, input_col, input_width, 1);

    int field_row = input_row + 1;
    int field_col = input_col + 2;

    if (read_password(password, MAX_PASSWORD, field_row, field_col) < 0)
        return -1;

    if (strlen(password) == 0) {
        printf("\033[%d;%dH\033[31mPassword cannot be empty\033[0m", input_row + 2, input_col + 2);
        fflush(stdout);
        sleep(1);
        return 0;
    }

    return 1;
}

static void setup_user_environment(struct passwd *pw) {
    char xauth_path[256];

    setenv("HOME", pw->pw_dir, 1);
    setenv("SHELL", pw->pw_shell, 1);
    setenv("USER", pw->pw_name, 1);
    setenv("LOGNAME", pw->pw_name, 1);
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/bin", 1);
    setenv("PWD", pw->pw_dir, 1);
    setenv("DISPLAY", ":0", 1);

    snprintf(xauth_path, sizeof(xauth_path), "%s/.Xauthority", pw->pw_dir);
    setenv("XAUTHORITY", xauth_path, 1);

    setenv("XDG_SESSION_TYPE", "x11", 1);
    setenv("XDG_SESSION_CLASS", "user", 1);
    setenv("XDG_SEAT", "seat0", 1);
    setenv("XDG_VTNR", "1", 1);

    if (chdir(pw->pw_dir) != 0) {
        chdir("/");
    }
}

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
        if (pam_open_session(pamh, 0) != PAM_SUCCESS) {
            fprintf(stderr, "Failed to open PAM session\n");
            exit(1);
        }

        setup_user_environment(pw);

        if (init_groups(pw) != 0) {
            exit(1);
        }

        char *argv[64];
        int argc = 0;
        char *cmd_copy = strdup(session_cmd);
        char *token = strtok(cmd_copy, " ");

        while (token && argc < 63) {
            argv[argc++] = token;
            token = strtok(NULL, " ");
        }
        argv[argc] = NULL;

        if (argc > 0 && strcmp(argv[0], "startx") == 0) {
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

        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }

        execvp(argv[0], argv);

        fprintf(stderr, "Failed to execute %s: %s\n", argv[0], strerror(errno));
        exit(1);
    }

    int status;
    waitpid(pid, &status, 0);

    pam_close_session(pamh, 0);

    return 0;
}

static int authenticate(const char *username, const char *password) {
    pam_handle_t *pamh = NULL;
    struct pam_conv conv = {
        pam_conversation,
        (void *)password
    };

    int retval;

    retval = pam_start("termdm", username, &conv, &pamh);
    if (retval != PAM_SUCCESS) {
        fprintf(stderr, "pam_start failed: %s\n", pam_strerror(pamh, retval));
        return -1;
    }

    retval = pam_authenticate(pamh, 0);
    if (retval != PAM_SUCCESS) {
        fprintf(stderr, "Authentication failed: %s\n", pam_strerror(pamh, retval));
        pam_end(pamh, retval);
        return -1;
    }

    retval = pam_acct_mgmt(pamh, 0);
    if (retval != PAM_SUCCESS) {
        fprintf(stderr, "Account validation failed: %s\n", pam_strerror(pamh, retval));
        pam_end(pamh, retval);
        return -1;
    }

    start_session(username, pamh);

    pam_end(pamh, PAM_SUCCESS);

    return 0;
}

int main(void) {
    char password[MAX_PASSWORD];

    if (getuid() != 0) {
        fprintf(stderr, "termdm must be run as root\n");
        return 1;
    }

    load_config();
    get_term_size();

    while (1) {
        memset(password, 0, sizeof(password));

        int result = display_login(password);

        if (result < 0) {
            printf("\033[2J\033[H\033[?25h");
            break;
        }

        if (result == 0) {
            continue;
        }

        printf("\033[2J\033[H");
        int msg_row = term_rows / 2;
        int msg_col = (term_cols - 20) / 2;
        printf("\033[%d;%dHAuthenticating...", msg_row, msg_col);
        fflush(stdout);

        if (authenticate(default_username, password) == 0) {
            memset(password, 0, sizeof(password));
            continue;
        } else {
            printf("\033[2J\033[H");
            int err_row = term_rows / 2;
            int err_col = (term_cols - 25) / 2;
            printf("\033[%d;%dH\033[31mAuthentication failed!\033[0m", err_row, err_col);
            fflush(stdout);
            sleep(2);
            memset(password, 0, sizeof(password));
        }
    }

    printf("\033[?25h\033[2J\033[H");

    return 0;
}
