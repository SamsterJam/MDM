#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <termios.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#define MAX_PASSWORD 256
#define MAX_USERS 64
#define MAX_SESSIONS 32
#define MAX_NAME 128
#define CONFIG_FILE "/etc/termdm/config"
#define STATE_FILE "/var/cache/termdm/state"
#define MIN_UID 1000

typedef struct {
    char username[MAX_NAME];
    char homedir[256];
    uid_t uid;
} User;

typedef struct {
    char name[MAX_NAME];
    char exec[256];
    char type[16];
} Session;

static int term_rows = 24;
static int term_cols = 80;
static User users[MAX_USERS];
static int user_count = 0;
static Session sessions[MAX_SESSIONS];
static int session_count = 0;
static int current_user = 0;
static int current_session = 0;

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

static int is_valid_shell(const char *shell) {
    const char *invalid[] = {"/bin/false", "/usr/bin/false",
                            "/sbin/nologin", "/usr/sbin/nologin",
                            "/usr/bin/nologin", "/bin/nologin", NULL};
    for (int i = 0; invalid[i]; i++) {
        if (strcmp(shell, invalid[i]) == 0)
            return 0;
    }
    return 1;
}

static void detect_users(void) {
    struct passwd *pw;
    setpwent();

    while ((pw = getpwent()) != NULL && user_count < MAX_USERS) {
        if (pw->pw_uid >= MIN_UID && pw->pw_uid < 60000 &&
            pw->pw_shell && is_valid_shell(pw->pw_shell)) {
            strncpy(users[user_count].username, pw->pw_name, MAX_NAME - 1);
            users[user_count].username[MAX_NAME - 1] = '\0';
            strncpy(users[user_count].homedir, pw->pw_dir, 255);
            users[user_count].homedir[255] = '\0';
            users[user_count].uid = pw->pw_uid;
            user_count++;
        }
    }

    endpwent();

    if (user_count == 0) {
        fprintf(stderr, "No valid users found (need UID >= %d and < 60000 with valid shell)\n", MIN_UID);
        fprintf(stderr, "Debug: getent passwd | awk -F: '$3 >= %d && $3 < 60000 {print $1, $3, $7}'\n", MIN_UID);
        exit(1);
    }
}

static void parse_desktop_file(const char *filepath, const char *type) {
    FILE *f = fopen(filepath, "r");
    if (!f) return;

    char line[512];
    char name[MAX_NAME] = {0};
    char exec[256] = {0};

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Name=", 5) == 0) {
            strncpy(name, line + 5, MAX_NAME - 1);
            char *nl = strchr(name, '\n');
            if (nl) *nl = '\0';
        } else if (strncmp(line, "Exec=", 5) == 0) {
            strncpy(exec, line + 5, 255);
            char *nl = strchr(exec, '\n');
            if (nl) *nl = '\0';
        }
    }

    fclose(f);

    if (name[0] && exec[0] && session_count < MAX_SESSIONS) {
        strncpy(sessions[session_count].name, name, MAX_NAME - 1);
        strncpy(sessions[session_count].exec, exec, 255);
        strncpy(sessions[session_count].type, type, 15);
        session_count++;
    }
}

static void detect_sessions(void) {
    const char *dirs[] = {"/usr/share/xsessions", "/usr/share/wayland-sessions"};
    const char *types[] = {"x11", "wayland"};

    for (int d = 0; d < 2; d++) {
        DIR *dir = opendir(dirs[d]);
        if (!dir) continue;

        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strstr(entry->d_name, ".desktop")) {
                char path[512];
                snprintf(path, sizeof(path), "%s/%s", dirs[d], entry->d_name);
                parse_desktop_file(path, types[d]);
            }
        }
        closedir(dir);
    }

    if (session_count == 0) {
        strncpy(sessions[0].name, "startx", MAX_NAME - 1);
        strncpy(sessions[0].exec, "startx", 255);
        strncpy(sessions[0].type, "x11", 15);
        session_count = 1;
    }
}

static void load_state(char *display_name) {
    FILE *f = fopen(STATE_FILE, "r");
    if (!f) return;

    char line[256];
    char last_user[MAX_NAME] = {0};
    char last_session[MAX_NAME] = {0};

    while (fgets(line, sizeof(line), f)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;

        *eq = '\0';
        char *value = eq + 1;
        char *nl = strchr(value, '\n');
        if (nl) *nl = '\0';

        if (strcmp(line, "last_user") == 0)
            strncpy(last_user, value, MAX_NAME - 1);
        else if (strcmp(line, "last_session") == 0)
            strncpy(last_session, value, MAX_NAME - 1);
        else if (strcmp(line, "display_name") == 0)
            strncpy(display_name, value, MAX_NAME - 1);
    }

    fclose(f);

    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, last_user) == 0) {
            current_user = i;
            break;
        }
    }

    for (int i = 0; i < session_count; i++) {
        if (strcmp(sessions[i].name, last_session) == 0) {
            current_session = i;
            break;
        }
    }
}

static void save_state(const char *display_name) {
    mkdir("/var/cache/termdm", 0755);

    FILE *f = fopen(STATE_FILE, "w");
    if (!f) return;

    fprintf(f, "last_user=%s\n", users[current_user].username);
    fprintf(f, "last_session=%s\n", sessions[current_session].name);
    fprintf(f, "display_name=%s\n", display_name);

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

static void draw_title(int start_row, int start_col, int box_width, const char *username, int highlighted) {
    FILE *fp;
    char command[512];
    char line[256];
    int line_count = 0;
    char *lines[32];

    snprintf(command, sizeof(command), "figlet -f standard '%s'", username);
    fp = popen(command, "r");

    if (!fp) {
        return;
    }

    while (fgets(line, sizeof(line), fp) && line_count < 32) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        lines[line_count] = strdup(line);
        line_count++;
    }

    pclose(fp);

    const char *color_start = highlighted ? "\033[1;36m" : "\033[1m";

    for (int i = 0; i < line_count; i++) {
        int len = strlen(lines[i]);
        int col = start_col + (box_width - len) / 2 + 1;
        if (col < start_col + 1) col = start_col + 1;
        printf("\033[%d;%dH%s%s\033[0m", start_row + i + 3, col, color_start, lines[i]);
        free(lines[i]);
    }
}

static void draw_session_selector(int row, int col, int is_active) {
    char display[128];
    int len;

    if (is_active) {
        snprintf(display, sizeof(display), "\033[1;36m<\033[0m \033[1m%s\033[0m \033[1;36m>\033[0m",
                sessions[current_session].name);
    } else {
        snprintf(display, sizeof(display), "\033[2m  %s  \033[0m",
                sessions[current_session].name);
    }

    len = strlen(sessions[current_session].name) + 4;
    int start_col = col - len / 2;
    printf("\033[%d;%dH%s", row, start_col, display);
}

static void to_lowercase(char *dest, const char *src, size_t size) {
    size_t i;
    for (i = 0; i < size - 1 && src[i] != '\0'; i++) {
        if (src[i] >= 'A' && src[i] <= 'Z') {
            dest[i] = src[i] + ('a' - 'A');
        } else {
            dest[i] = src[i];
        }
    }
    dest[i] = '\0';
}

static int handle_input(char *username, char *password, int max_len, int *pass_pos, int *user_pos,
                       int *active_field, int *user_edit_mode, int user_row, int pass_row,
                       int pass_col, int session_row, int center_col,
                       int start_row, int start_col, int box_width) {
    struct termios old, new;

    tcgetattr(STDIN_FILENO, &old);
    new = old;
    new.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSANOW, &new);

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
                printf("\033[2J\033[H\033[?25l");
                draw_box(start_row, start_col, box_width, 13);
                draw_title(start_row, start_col, box_width, username, 0);
                draw_box(pass_row - 1, start_col + 4, box_width - 6, 1);
                draw_session_selector(session_row, center_col, 0);
            }
            int old_field = *active_field;
            *active_field = (*active_field + 1) % 3;
            if (old_field == 0 && !*user_edit_mode) {
                printf("\033[2J\033[H\033[?25l");
                draw_box(start_row, start_col, box_width, 13);
                draw_title(start_row, start_col, box_width, username, 0);
                draw_box(pass_row - 1, start_col + 4, box_width - 6, 1);
                draw_session_selector(session_row, center_col, 0);
            } else if (*active_field == 0 && !*user_edit_mode) {
                printf("\033[2J\033[H\033[?25l");
                draw_box(start_row, start_col, box_width, 13);
                draw_title(start_row, start_col, box_width, username, 1);
                draw_box(pass_row - 1, start_col + 4, box_width - 6, 1);
                draw_session_selector(session_row, center_col, 0);
            }
            draw_session_selector(session_row, center_col, *active_field == 2);
            fflush(stdout);
            continue;
        }

        if (c == 27) {
            c = getchar();
            if (c == '[') {
                c = getchar();
                if (*active_field == 2) {
                    if (c == 'D' || c == 'C') {
                        if (c == 'D') {
                            current_session = (current_session + session_count - 1) % session_count;
                        } else {
                            current_session = (current_session + 1) % session_count;
                        }
                        printf("\033[%d;%dH                                        ", session_row, center_col - 20);
                        draw_session_selector(session_row, center_col, 1);
                        fflush(stdout);
                    }
                }
            }
            continue;
        }

        if (*active_field == 0) {
            if (*user_edit_mode) {
                if (c == '\n' || c == '\r') {
                    *user_edit_mode = 0;
                    printf("\033[2J\033[H\033[?25l");
                    draw_box(start_row, start_col, box_width, 13);
                    draw_title(start_row, start_col, box_width, username, 1);
                    draw_box(pass_row - 1, start_col + 4, box_width - 6, 1);
                    draw_session_selector(session_row, center_col, 0);
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
                draw_session_selector(session_row, center_col, 0);
                fflush(stdout);
            }
        }
    }

    printf("\033[?25l");
    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    return 0;
}

static int display_login(char *password, char *username) {
    int box_width = 70;
    int box_height = 13;
    int start_col = (term_cols - box_width - 2) / 2;
    int start_row = (term_rows - box_height - 2) / 2;

    if (start_col < 1) start_col = 1;
    if (start_row < 1) start_row = 1;

    printf("\033[2J\033[H\033[?25l");

    draw_box(start_row, start_col, box_width, box_height);
    draw_title(start_row, start_col, box_width, username, 0);

    int user_row = start_row + 9;
    int center_col = start_col + box_width / 2 + 1;

    int input_row = start_row + 10;
    int input_col = start_col + 4;
    int input_width = box_width - 6;

    draw_box(input_row, input_col, input_width, 1);

    int field_row = input_row + 1;
    int field_col = input_col + 2;

    int session_row = input_row + 4;

    draw_session_selector(session_row, center_col, 0);

    int active_field = 1;
    int pass_pos = 0;
    int user_pos = strlen(username);
    int user_edit_mode = 0;

    if (handle_input(username, password, MAX_PASSWORD, &pass_pos, &user_pos, &active_field,
                    &user_edit_mode, user_row, field_row, field_col, session_row, center_col,
                    start_row, start_col, box_width) < 0)
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
    char runtime_dir[256];

    setenv("HOME", pw->pw_dir, 1);
    setenv("SHELL", pw->pw_shell, 1);
    setenv("USER", pw->pw_name, 1);
    setenv("LOGNAME", pw->pw_name, 1);
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/bin", 1);
    setenv("PWD", pw->pw_dir, 1);
    setenv("DISPLAY", ":0", 1);

    snprintf(xauth_path, sizeof(xauth_path), "%s/.Xauthority", pw->pw_dir);
    setenv("XAUTHORITY", xauth_path, 1);

    snprintf(runtime_dir, sizeof(runtime_dir), "/run/user/%d", pw->pw_uid);
    setenv("XDG_RUNTIME_DIR", runtime_dir, 1);

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

        if (strcmp(sessions[current_session].type, "wayland") == 0) {
            setenv("XDG_SESSION_TYPE", "wayland", 1);
        } else {
            setenv("XDG_SESSION_TYPE", "x11", 1);
        }

        if (init_groups(pw) != 0) {
            exit(1);
        }

        char *argv[64];
        int argc = 0;

        if (strcmp(sessions[current_session].type, "x11") == 0) {
            argv[argc++] = "xinit";

            char *cmd_copy = strdup(sessions[current_session].exec);
            char *token = strtok(cmd_copy, " ");
            while (token && argc < 60) {
                argv[argc++] = token;
                token = strtok(NULL, " ");
            }

            argv[argc++] = "--";
            argv[argc++] = ":0";
            argv[argc++] = "vt1";
            argv[argc] = NULL;
        } else {
            char *cmd_copy = strdup(sessions[current_session].exec);
            char *token = strtok(cmd_copy, " ");

            while (token && argc < 63) {
                argv[argc++] = token;
                token = strtok(NULL, " ");
            }
            argv[argc] = NULL;
        }

        char logfile[512];
        snprintf(logfile, sizeof(logfile), "%s/.termdm-session.log", pw->pw_dir);
        int logfd = open(logfile, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (logfd >= 0) {
            dup2(logfd, STDOUT_FILENO);
            dup2(logfd, STDERR_FILENO);
            close(logfd);
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
    char username[MAX_NAME];
    char display_name[MAX_NAME] = {0};

    if (getuid() != 0) {
        fprintf(stderr, "termdm must be run as root\n");
        return 1;
    }

    get_term_size();
    detect_users();
    detect_sessions();
    load_state(display_name);

    if (display_name[0] != '\0') {
        strncpy(username, display_name, MAX_NAME - 1);
    } else {
        strncpy(username, users[current_user].username, MAX_NAME - 1);
    }
    username[MAX_NAME - 1] = '\0';

    while (1) {
        memset(password, 0, sizeof(password));

        int result = display_login(password, username);

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

        char username_lower[MAX_NAME];
        to_lowercase(username_lower, username, MAX_NAME);

        if (authenticate(username_lower, password) == 0) {
            for (int i = 0; i < user_count; i++) {
                if (strcmp(users[i].username, username_lower) == 0) {
                    current_user = i;
                    break;
                }
            }
            strncpy(display_name, username, MAX_NAME - 1);
            display_name[MAX_NAME - 1] = '\0';
            save_state(display_name);
            memset(password, 0, sizeof(password));
            strncpy(username, display_name, MAX_NAME - 1);
            username[MAX_NAME - 1] = '\0';
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
