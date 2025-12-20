#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "config.h"
#include "log.h"

static void config_set_defaults(ColorConfig *config) {
    memcpy(config->background, "282c34\0", 7);
    memcpy(config->border, "61afef\0", 7);
    memcpy(config->ascii_art, "ffffff\0", 7);
    memcpy(config->ascii_highlight, "56b6c2\0", 7);
    memcpy(config->selector, "56b6c2\0", 7);
    memcpy(config->session, "abb2bf\0", 7);
    memcpy(config->password, "ffffff\0", 7);
    memcpy(config->error, "e06c75\0", 7);
    memcpy(config->info, "98c379\0", 7);
    memcpy(config->power_hotkeys, "abb2bf\0", 7);
    memcpy(config->suspend_hotkey, "F3\0", 3);
    memcpy(config->shutdown_hotkey, "F4\0", 3);
    memcpy(config->reboot_hotkey, "F5\0", 3);
    config->show_power_hotkeys = 1;
}

static void trim(char *str) {
    char *start = str;
    char *end;

    while (isspace((unsigned char)*start)) start++;
    if (*start == 0) {
        *str = 0;
        return;
    }

    end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) end--;
    end[1] = '\0';

    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }
}

static int is_valid_hex(const char *hex) {
    if (strlen(hex) != 6) return 0;
    for (int i = 0; i < 6; i++) {
        if (!isxdigit((unsigned char)hex[i])) return 0;
    }
    return 1;
}

int config_load(const char *config_path, ColorConfig *config) {
    FILE *f;
    char line[256];
    char key[64], value[64];

    config_set_defaults(config);

    f = fopen(config_path, "r");
    if (!f) {
        // Config file doesn't exist, use defaults
        return 0;
    }

    while (fgets(line, sizeof(line), f)) {
        char *comment = strchr(line, '#');
        if (comment) *comment = '\0';

        trim(line);
        if (line[0] == '\0') continue;

        char *eq = strchr(line, '=');
        if (!eq) continue;

        *eq = '\0';
        strncpy(key, line, sizeof(key) - 1);
        key[sizeof(key) - 1] = '\0';
        strncpy(value, eq + 1, sizeof(value) - 1);
        value[sizeof(value) - 1] = '\0';

        trim(key);
        trim(value);

        // Boolean settings
        if (strcmp(key, "show_power_hotkeys") == 0) {
            if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0) {
                config->show_power_hotkeys = 1;
            } else if (strcmp(value, "false") == 0 || strcmp(value, "0") == 0) {
                config->show_power_hotkeys = 0;
            }
        }
        // Hotkey settings don't need hex validation
        else if (strcmp(key, "suspend_hotkey") == 0) {
            strncpy(config->suspend_hotkey, value, 4);
            config->suspend_hotkey[4] = '\0';
        } else if (strcmp(key, "shutdown_hotkey") == 0) {
            strncpy(config->shutdown_hotkey, value, 4);
            config->shutdown_hotkey[4] = '\0';
        } else if (strcmp(key, "reboot_hotkey") == 0) {
            strncpy(config->reboot_hotkey, value, 4);
            config->reboot_hotkey[4] = '\0';
        } else {
            // Color settings need hex validation
            if (!is_valid_hex(value)) {
                log_warnf("Invalid hex color '%s' for '%s'", value, key);
                continue;
            }

            // Map to config structure
            if (strcmp(key, "background") == 0) {
                strncpy(config->background, value, 6);
            } else if (strcmp(key, "border") == 0) {
                strncpy(config->border, value, 6);
            } else if (strcmp(key, "ascii_art") == 0) {
                strncpy(config->ascii_art, value, 6);
            } else if (strcmp(key, "ascii_highlight") == 0) {
                strncpy(config->ascii_highlight, value, 6);
            } else if (strcmp(key, "selector") == 0) {
                strncpy(config->selector, value, 6);
            } else if (strcmp(key, "session") == 0) {
                strncpy(config->session, value, 6);
            } else if (strcmp(key, "password") == 0) {
                strncpy(config->password, value, 6);
            } else if (strcmp(key, "error") == 0) {
                strncpy(config->error, value, 6);
            } else if (strcmp(key, "info") == 0) {
                strncpy(config->info, value, 6);
            } else if (strcmp(key, "power_hotkeys") == 0) {
                strncpy(config->power_hotkeys, value, 6);
            }
        }
    }

    fclose(f);
    return 0;
}

void config_apply_tty_colors(const ColorConfig *config) {
    /* Map UI elements to TTY color slots:
     * 0 = background
     * 1 = error (red slot)
     * 2 = info (green slot)
     * 3 = session (yellow slot)
     * 4 = border (blue slot)
     * 5 = selector (magenta slot)
     * 6 = ascii_highlight (cyan slot)
     * 7 = ascii_art (white slot)
     * 8 = power_hotkeys (bright black/dim)
     * 9-15 = unused for now
     */

    printf("\e]P0%s", config->background);
    printf("\e]P1%s", config->error);
    printf("\e]P2%s", config->info);
    printf("\e]P3%s", config->session);
    printf("\e]P4%s", config->border);
    printf("\e]P5%s", config->selector);
    printf("\e]P6%s", config->ascii_highlight);
    printf("\e]P7%s", config->ascii_art);
    printf("\e]P8%s", config->power_hotkeys);
    printf("\e]P9%s", config->error);
    printf("\e]PA%s", config->info);
    printf("\e]PB%s", config->session);
    printf("\e]PC%s", config->border);
    printf("\e]PD%s", config->selector);
    printf("\e]PE%s", config->ascii_highlight);
    printf("\e]PF%s", config->ascii_art);

    // Clear screen to apply background
    printf("\033[2J\033[H");
    fflush(stdout);
}

const char* config_get_ansi_color(const char *element) {
    // Return ANSI codes that reference the TTY color slots we set up
    if (strcmp(element, "background") == 0) {
        return "\033[40m";
    } else if (strcmp(element, "border") == 0) {
        return "\033[34m";
    } else if (strcmp(element, "ascii_art") == 0) {
        return "\033[1;37m";
    } else if (strcmp(element, "ascii_highlight") == 0) {
        return "\033[1;36m";
    } else if (strcmp(element, "selector") == 0) {
        return "\033[1;36m";
    } else if (strcmp(element, "session") == 0) {
        return "\033[33m";
    } else if (strcmp(element, "session_dim") == 0) {
        return "\033[2;33m";
    } else if (strcmp(element, "password") == 0) {
        return "\033[37m";
    } else if (strcmp(element, "error") == 0) {
        return "\033[31m";
    } else if (strcmp(element, "info") == 0) {
        return "\033[32m";
    } else if (strcmp(element, "power_hotkeys") == 0) {
        return "\033[90m";
    }

    return "\033[0m";
}
