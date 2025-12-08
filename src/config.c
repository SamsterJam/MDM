#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "config.h"

/* Default color configuration (One Dark theme) */
static void config_set_defaults(ColorConfig *config) {
    strcpy(config->background, "282c34");
    strcpy(config->border, "61afef");
    strcpy(config->ascii_art, "ffffff");
    strcpy(config->ascii_highlight, "56b6c2");
    strcpy(config->selector, "56b6c2");
    strcpy(config->session, "abb2bf");
    strcpy(config->password, "ffffff");
    strcpy(config->error, "e06c75");
    strcpy(config->info, "98c379");
}

/* Trim whitespace from string */
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

/* Validate hex color code */
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

    /* Set defaults first */
    config_set_defaults(config);

    f = fopen(config_path, "r");
    if (!f) {
        /* Config file doesn't exist, use defaults */
        return 0;
    }

    while (fgets(line, sizeof(line), f)) {
        /* Skip comments and empty lines */
        char *comment = strchr(line, '#');
        if (comment) *comment = '\0';

        trim(line);
        if (line[0] == '\0') continue;

        /* Parse key=value */
        char *eq = strchr(line, '=');
        if (!eq) continue;

        *eq = '\0';
        strncpy(key, line, sizeof(key) - 1);
        strncpy(value, eq + 1, sizeof(value) - 1);
        key[sizeof(key) - 1] = '\0';
        value[sizeof(value) - 1] = '\0';

        trim(key);
        trim(value);

        /* Validate and store hex color */
        if (!is_valid_hex(value)) {
            fprintf(stderr, "Warning: Invalid hex color '%s' for '%s'\n", value, key);
            continue;
        }

        /* Map to config structure */
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
     * 8 = dim (bright black)
     * 9-15 = unused for now
     */

    printf("\e]P0%s", config->background);      /* Color 0: background */
    printf("\e]P1%s", config->error);           /* Color 1: error */
    printf("\e]P2%s", config->info);            /* Color 2: info */
    printf("\e]P3%s", config->session);         /* Color 3: session */
    printf("\e]P4%s", config->border);          /* Color 4: border */
    printf("\e]P5%s", config->selector);        /* Color 5: selector */
    printf("\e]P6%s", config->ascii_highlight); /* Color 6: ascii_highlight */
    printf("\e]P7%s", config->ascii_art);       /* Color 7: ascii_art */
    printf("\e]P8%s", "5c6370");                /* Color 8: dim gray */
    printf("\e]P9%s", config->error);           /* Color 9: bright error */
    printf("\e]PA%s", config->info);            /* Color 10: bright info */
    printf("\e]PB%s", config->session);         /* Color 11: bright session */
    printf("\e]PC%s", config->border);          /* Color 12: bright border */
    printf("\e]PD%s", config->selector);        /* Color 13: bright selector */
    printf("\e]PE%s", config->ascii_highlight); /* Color 14: bright highlight */
    printf("\e]PF%s", config->ascii_art);       /* Color 15: bright ascii */

    /* Clear screen to apply background */
    printf("\033[2J\033[H");
    fflush(stdout);
}

const char* config_get_ansi_color(const ColorConfig *config, const char *element) {
    /* Return ANSI codes that reference the TTY color slots we set up */
    if (strcmp(element, "background") == 0) {
        return "\033[40m";  /* Background color 0 */
    } else if (strcmp(element, "border") == 0) {
        return "\033[34m";  /* Blue slot (color 4) */
    } else if (strcmp(element, "ascii_art") == 0) {
        return "\033[1;37m";  /* Bold white (color 7) */
    } else if (strcmp(element, "ascii_highlight") == 0) {
        return "\033[1;36m";  /* Bold cyan (color 6) */
    } else if (strcmp(element, "selector") == 0) {
        return "\033[1;36m";  /* Bold cyan (color 6) */
    } else if (strcmp(element, "session") == 0) {
        return "\033[33m";  /* Yellow slot (color 3) */
    } else if (strcmp(element, "session_dim") == 0) {
        return "\033[2;33m";  /* Dim yellow */
    } else if (strcmp(element, "password") == 0) {
        return "\033[37m";  /* White (color 7) */
    } else if (strcmp(element, "error") == 0) {
        return "\033[31m";  /* Red slot (color 1) */
    } else if (strcmp(element, "info") == 0) {
        return "\033[32m";  /* Green slot (color 2) */
    }

    return "\033[0m";  /* Reset */
}
