/*
 * MDM - Minimal Display Manager
 * A lightweight terminal-based display manager
 * Dependencies: PAM, systemd (for journal logging)
 */

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
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include "types.h"
#include "figlet.h"
#include "config.h"
#include "tui.h"
#include "log.h"

#define MAX_PASSWORD 256
#define MAX_USERS 64
#define MAX_SESSIONS 32
#define CONFIG_FILE "/etc/mdm/mdm.conf"
#define STATE_FILE "/var/cache/mdm/state"
#define MIN_UID 1000
#define FONT_FILE "/usr/share/mdm/standard.flf"
#define FONT_FILE_SMALL "/usr/share/mdm/small.flf"
#define FONT_FILE_MINI "/usr/share/mdm/mini.flf"

static User users[MAX_USERS];
static int user_count = 0;
static Session sessions[MAX_SESSIONS];
static int session_count = 0;
static int current_user = 0;
static int current_session = 0;
static ColorConfig colors;

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
                if (!reply[i].resp) {
                    /* strdup failed - cleanup and return error */
                    for (int j = 0; j < i; j++) {
                        if (reply[j].resp) {
                            free(reply[j].resp);
                        }
                    }
                    free(reply);
                    return PAM_BUF_ERR;
                }
                reply[i].resp_retcode = 0;
                break;
            case PAM_PROMPT_ECHO_ON:
            case PAM_ERROR_MSG:
            case PAM_TEXT_INFO:
                reply[i].resp = NULL;
                reply[i].resp_retcode = 0;
                break;
            default:
                /* Cleanup on error */
                for (int j = 0; j < i; j++) {
                    if (reply[j].resp) {
                        free(reply[j].resp);
                    }
                }
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
        log_criticalf("No valid users found (need UID >= %d and < 60000 with valid shell)", MIN_UID);
        log_debugf("Debug: getent passwd | awk -F: '$3 >= %d && $3 < 60000 {print $1, $3, $7}'", MIN_UID);
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
            snprintf(name, MAX_NAME, "%.127s", line + 5);
            char *nl = strchr(name, '\n');
            if (nl) *nl = '\0';
        } else if (strncmp(line, "Exec=", 5) == 0) {
            snprintf(exec, sizeof(exec), "%.255s", line + 5);
            char *nl = strchr(exec, '\n');
            if (nl) *nl = '\0';
        }
    }

    fclose(f);

    if (name[0] && exec[0] && session_count < MAX_SESSIONS) {
        snprintf(sessions[session_count].name, MAX_NAME, "%s", name);
        snprintf(sessions[session_count].exec, sizeof(sessions[session_count].exec), "%s", exec);
        snprintf(sessions[session_count].type, sizeof(sessions[session_count].type), "%s", type);
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
                if (strstr(entry->d_name, "uwsm")) {
                    continue;
                }
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

        if (strcmp(line, "last_user") == 0) {
            strncpy(last_user, value, MAX_NAME - 1);
            last_user[MAX_NAME - 1] = '\0';
        } else if (strcmp(line, "last_session") == 0) {
            strncpy(last_session, value, MAX_NAME - 1);
            last_session[MAX_NAME - 1] = '\0';
        } else if (strcmp(line, "display_name") == 0) {
            strncpy(display_name, value, MAX_NAME - 1);
            display_name[MAX_NAME - 1] = '\0';
        }
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
    mkdir("/var/cache/mdm", 0700);

    FILE *f = fopen(STATE_FILE, "w");
    if (!f) return;

    if (current_user >= 0 && current_user < user_count)
        fprintf(f, "last_user=%s\n", users[current_user].username);
    if (current_session >= 0 && current_session < session_count)
        fprintf(f, "last_session=%s\n", sessions[current_session].name);
    fprintf(f, "display_name=%s\n", display_name);

    fclose(f);
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

static int get_vt_number(void) {
    // Get the current TTY device name
    char *tty = ttyname(STDIN_FILENO);
    if (!tty) {
        tty = ttyname(STDOUT_FILENO);
    }
    if (!tty) {
        // Fallback to tty1
        return 1;
    }

    char *vt_str = NULL;
    if (strncmp(tty, "/dev/tty", 8) == 0) {
        vt_str = tty + 8;
    } else if (strncmp(tty, "/dev/vc/", 8) == 0) {
        vt_str = tty + 8;
    }

    if (vt_str && *vt_str >= '0' && *vt_str <= '9') {
        return atoi(vt_str);
    }

    // Default to VT1
    return 1;
}

static void setup_user_environment(struct passwd *pw, const char *session_type, int vt_number) {
    char xauth_path[256];
    char runtime_dir[256];
    char display[16];
    char vtnr[8];

    setenv("HOME", pw->pw_dir, 1);
    setenv("SHELL", pw->pw_shell, 1);
    setenv("USER", pw->pw_name, 1);
    setenv("LOGNAME", pw->pw_name, 1);
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin", 1);
    setenv("PWD", pw->pw_dir, 1);

    snprintf(display, sizeof(display), ":%d", vt_number - 1);
    setenv("DISPLAY", display, 1);

    snprintf(xauth_path, sizeof(xauth_path), "%s/.Xauthority", pw->pw_dir);
    setenv("XAUTHORITY", xauth_path, 1);

    snprintf(runtime_dir, sizeof(runtime_dir), "/run/user/%d", pw->pw_uid);
    setenv("XDG_RUNTIME_DIR", runtime_dir, 1);

    setenv("XDG_SESSION_TYPE", session_type, 1);
    setenv("XDG_SESSION_CLASS", "user", 1);
    setenv("XDG_SEAT", "seat0", 1);

    snprintf(vtnr, sizeof(vtnr), "%d", vt_number);
    setenv("XDG_VTNR", vtnr, 1);

    setenv("XDG_SESSION_DESKTOP", sessions[current_session].name, 1);
    setenv("XDG_CURRENT_DESKTOP", sessions[current_session].name, 1);
    setenv("DESKTOP_SESSION", sessions[current_session].name, 1);

    if (chdir(pw->pw_dir) != 0) {
        chdir("/");
    }
}

static int init_groups(struct passwd *pw) {
    if (initgroups(pw->pw_name, pw->pw_gid) != 0) {
        log_errorf("initgroups failed for user %s: %s", pw->pw_name, strerror(errno));
        return -1;
    }

    if (setgid(pw->pw_gid) != 0) {
        log_errorf("setgid failed for GID %d: %s", pw->pw_gid, strerror(errno));
        return -1;
    }

    if (setuid(pw->pw_uid) != 0) {
        log_errorf("setuid failed for UID %d: %s", pw->pw_uid, strerror(errno));
        return -1;
    }

    return 0;
}

static int start_session(const char *username, pam_handle_t *pamh) {
    struct passwd *pw = getpwnam(username);
    if (!pw) {
        log_errorf("User %s not found", username);
        return -1;
    }

    int vt_number = get_vt_number();

    // Set PAM environment variables BEFORE opening session so pam_systemd registers the correct session type
    char pam_env_buf[256];

    snprintf(pam_env_buf, sizeof(pam_env_buf), "XDG_SESSION_TYPE=%s", sessions[current_session].type);
    pam_putenv(pamh, pam_env_buf);

    pam_putenv(pamh, "XDG_SESSION_CLASS=user");
    pam_putenv(pamh, "XDG_SEAT=seat0");

    snprintf(pam_env_buf, sizeof(pam_env_buf), "XDG_VTNR=%d", vt_number);
    pam_putenv(pamh, pam_env_buf);

    snprintf(pam_env_buf, sizeof(pam_env_buf), "XDG_SESSION_DESKTOP=%s", sessions[current_session].name);
    pam_putenv(pamh, pam_env_buf);

    // Open PAM session before forking to allow pam_systemd to create /run/user/<uid> and register the session
    if (pam_open_session(pamh, 0) != PAM_SUCCESS) {
        log_error("Failed to open PAM session");
        return -1;
    }

    pid_t pid = fork();

    if (pid < 0) {
        log_errorf("fork failed: %s", strerror(errno));
        pam_close_session(pamh, 0);
        return -1;
    }

    if (pid == 0) {
        // Redirect stdout and stderr to /dev/null to prevent session output (X, Wayland, etc.) from cluttering TTY
        int devnull_child = open("/dev/null", O_WRONLY);
        if (devnull_child >= 0) {
            dup2(devnull_child, STDOUT_FILENO);
            dup2(devnull_child, STDERR_FILENO);
            close(devnull_child);
        }

        setup_user_environment(pw, sessions[current_session].type, vt_number);

        // Import environment variables set by pam_systemd
        char **pam_env = pam_getenvlist(pamh);
        if (pam_env) {
            for (int i = 0; pam_env[i]; i++) {
                char *eq = strchr(pam_env[i], '=');
                if (eq) {
                    *eq = '\0';
                    setenv(pam_env[i], eq + 1, 1);
                    *eq = '=';
                }
                free(pam_env[i]);
            }
            free(pam_env);
        }

        // Set dbus session address for systemd user sessions
        char dbus_addr[256];
        snprintf(dbus_addr, sizeof(dbus_addr), "unix:path=/run/user/%d/bus", pw->pw_uid);
        setenv("DBUS_SESSION_BUS_ADDRESS", dbus_addr, 1);

        if (init_groups(pw) != 0) {
            exit(1);
        }

        char *argv[64];
        int argc = 0;
        // Declare these outside the if block to ensure they remain in scope
        char display_arg[16];
        char vt_arg[16];
        char *shell_cmd = NULL;
        char *cmd_copy = NULL;

        if (strcmp(sessions[current_session].type, "x11") == 0) {
            // Build xinit command with dynamic display and vt
            // Use shell to execute the command - this ensures PATH is used correctly
            snprintf(display_arg, sizeof(display_arg), ":%d", vt_number - 1);
            snprintf(vt_arg, sizeof(vt_arg), "vt%d", vt_number);

            argv[argc++] = "xinit";
            argv[argc++] = "/bin/sh";
            argv[argc++] = "-c";

            // Build shell command that sources user's X startup files before launching session
            // This ensures .Xresources is loaded and xinitrc.d scripts run
            shell_cmd = malloc(1024);
            snprintf(shell_cmd, 1024,
                "[ -f /etc/xprofile ] && . /etc/xprofile; "
                "[ -f ~/.xprofile ] && . ~/.xprofile; "
                "[ -f ~/.Xresources ] && xrdb -merge ~/.Xresources; "
                "[ -d /etc/X11/xinit/xinitrc.d ] && for f in /etc/X11/xinit/xinitrc.d/?*.sh; do [ -x \"$f\" ] && . \"$f\"; done; "
                "exec %s", sessions[current_session].exec);
            argv[argc++] = shell_cmd;

            argv[argc++] = "--";
            argv[argc++] = display_arg;
            argv[argc++] = vt_arg;
            argv[argc] = NULL;
        } else {
            cmd_copy = strdup(sessions[current_session].exec);
            char *token = strtok(cmd_copy, " ");

            while (token && argc < 63) {
                argv[argc++] = token;
                token = strtok(NULL, " ");
            }
            argv[argc] = NULL;
        }

        // Log session start details to journal
        log_infof("Session starting for user %s (UID: %d, GID: %d)", pw->pw_name, pw->pw_uid, pw->pw_gid);
        log_infof("Session type: %s (%s)", sessions[current_session].name, sessions[current_session].type);
        log_debugf("Command: %s", sessions[current_session].exec);
        log_debugf("Home: %s, Shell: %s", pw->pw_dir, pw->pw_shell);
        log_debugf("PATH: %s", getenv("PATH"));
        log_debugf("DISPLAY: %s, XDG_RUNTIME_DIR: %s", getenv("DISPLAY"), getenv("XDG_RUNTIME_DIR"));

        execvp(argv[0], argv);

        // execvp only returns on failure - cleanup allocated memory
        if (shell_cmd) free(shell_cmd);
        if (cmd_copy) free(cmd_copy);

        log_criticalf("Failed to execute %s: %s (errno: %d)", argv[0], strerror(errno), errno);
        exit(1);
    }

    // Parent process
    int status;
    waitpid(pid, &status, 0);

    // Log session exit status to journal
    if (WIFEXITED(status)) {
        log_infof("Session ended for user %s, exit code: %d", username, WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        log_warnf("Session for user %s killed by signal: %d", username, WTERMSIG(status));
    } else {
        log_warnf("Session for user %s ended abnormally (status: %d)", username, status);
    }

    // Close PAM session after child exits to allow pam_systemd
    // to clean up /run/user/<uid> and unregister the session
    pam_close_session(pamh, 0);

    return 0;
}

static int authenticate(const char *username, const char *password, const char *display_name) {
    pam_handle_t *pamh = NULL;
    struct pam_conv conv = {
        pam_conversation,
        (void *)password
    };

    int retval;

    retval = pam_start("mdm", username, &conv, &pamh);
    if (retval != PAM_SUCCESS) {
        log_errorf("pam_start failed (error code %d)", retval);
        return -1;
    }

    retval = pam_authenticate(pamh, 0);
    if (retval != PAM_SUCCESS) {
        log_warnf("Authentication failed for user '%s': %s", username, pam_strerror(pamh, retval));
        pam_end(pamh, retval);
        return -1;
    }

    retval = pam_acct_mgmt(pamh, 0);
    if (retval != PAM_SUCCESS) {
        log_errorf("Account validation failed for user '%s': %s", username, pam_strerror(pamh, retval));
        pam_end(pamh, retval);
        return -1;
    }

    // Save state BEFORE starting the session to ensure it persists even if session crashes
    save_state(display_name);

    start_session(username, pamh);

    pam_end(pamh, PAM_SUCCESS);

    return 0;
}

int main(void) {
    char password[MAX_PASSWORD];
    char username[MAX_NAME];
    char display_name[MAX_NAME] = {0};

    if (getuid() != 0) {
        log_critical("mdm must be run as root");
        return 1;
    }

    log_info("MDM starting");

    // Load color configuration
    config_load(CONFIG_FILE, &colors);

    // Apply TTY color palette
    config_apply_tty_colors(&colors);

    // Initialize FIGlet font
    if (figlet_init(FONT_FILE) != 0) {
        log_warnf("Could not load font file %s", FONT_FILE);
    }

    tui_init();

    // Redirect stderr to /dev/null to prevent journal fallback from cluttering the TUI
    // Journal logging still works via sd_journal_send(), but stderr output is suppressed
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
        dup2(devnull, STDERR_FILENO);
        close(devnull);
    }

    detect_users();
    detect_sessions();
    load_state(display_name);

    // Validate display_name corresponds to an actual user
    if (display_name[0] != '\0') {
        char display_lower[MAX_NAME];
        to_lowercase(display_lower, display_name, MAX_NAME);
        int valid = 0;
        for (int i = 0; i < user_count; i++) {
            if (strcmp(users[i].username, display_lower) == 0) {
                valid = 1;
                break;
            }
        }
        if (!valid) {
            display_name[0] = '\0';  // Clear invalid display name
        }
    }

    if (display_name[0] != '\0') {
        strncpy(username, display_name, MAX_NAME - 1);
    } else {
        strncpy(username, users[current_user].username, MAX_NAME - 1);
    }
    username[MAX_NAME - 1] = '\0';

    while (1) {
        memset(password, 0, sizeof(password));

        int result = tui_display_login(username, password, users, user_count, sessions, session_count,
                                       &current_user, &current_session, &colors);

        if (result < 0) {
            printf("\033[2J\033[H\033[?25h");
            break;
        }

        if (result == 0) {
            continue;
        }

        tui_show_message("Authenticating...", config_get_ansi_color("info"));

        char username_lower[MAX_NAME];
        to_lowercase(username_lower, username, MAX_NAME);

        // Update current_user index before authentication
        for (int i = 0; i < user_count; i++) {
            if (strcmp(users[i].username, username_lower) == 0) {
                current_user = i;
                break;
            }
        }

        strncpy(display_name, username, MAX_NAME - 1);
        display_name[MAX_NAME - 1] = '\0';

        // Fork before authenticate to keep main process clean
        // This prevents systemd-logind from associating main mdm with any session
        pid_t auth_pid = fork();
        if (auth_pid < 0) {
            log_errorf("fork failed: %s", strerror(errno));
            tui_show_message("System error!", config_get_ansi_color("error"));
            sleep(2);
            memset(password, 0, sizeof(password));
            continue;
        }

        if (auth_pid == 0) {
            // Child process handles authentication and session
            int result = authenticate(username_lower, password, display_name);
            exit(result == 0 ? 0 : 1);
        }

        // Parent: wait for auth child to complete
        int auth_status;
        waitpid(auth_pid, &auth_status, 0);

        // Treat as successful logout if:
        // 1. Child exited normally with code 0 (typical X session logout)
        // 2. Child was terminated by signal (typical Wayland session cleanup by systemd-logind)
        if ((WIFEXITED(auth_status) && WEXITSTATUS(auth_status) == 0) || WIFSIGNALED(auth_status)) {
            // Session ended (user logged out) - clean up and return to login
            memset(password, 0, sizeof(password));
            strncpy(username, display_name, MAX_NAME - 1);
            username[MAX_NAME - 1] = '\0';

            // Reset terminal completely after session ends
            printf("\033c");  // Full terminal reset (ESC c)
            fflush(stdout);
            usleep(100000);  // 100ms to let terminal settle
            tui_init();
            continue;
        } else {
            // Only show auth failed if child actually exited with error code (not signal)
            tui_show_message("Authentication failed!", config_get_ansi_color("error"));
            sleep(2);
            memset(password, 0, sizeof(password));
        }
    }

    printf("\033[?25h\033[2J\033[H");

    figlet_cleanup();
    return 0;
}
