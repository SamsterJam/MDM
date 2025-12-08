/*
 * ascii.c - Lightweight FIGlet font parser and renderer
 * Part of MDM (Minimal Display Manager)
 *
 * This is a minimal implementation that parses FIGlet .flf font files
 * and renders text without requiring the external figlet binary.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ascii.h"

#define MAX_CHARS 128
#define MAX_LINES_PER_CHAR 10

typedef struct {
    char lines[MAX_LINES_PER_CHAR][MAX_CHAR_WIDTH + 1];
    int width;
} CharData;

static CharData font_chars[MAX_CHARS];
static int font_height = 0;
static int initialized = 0;

int ascii_init(const char *font_path) {
    FILE *f = fopen(font_path, "r");
    if (!f) {
        return -1;
    }

    char line[256];

    /* Read header line */
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return -1;
    }

    /* Parse header: flf2a$ height baseline max_length ... */
    char sig[6];
    int baseline, max_length, old_layout, comment_lines;
    if (sscanf(line, "%5s %d %d %d %d %d", sig, &font_height, &baseline,
               &max_length, &old_layout, &comment_lines) < 6) {
        fclose(f);
        return -1;
    }

    if (strncmp(sig, "flf2a", 5) != 0) {
        fclose(f);
        return -1;
    }

    /* Skip comment lines */
    for (int i = 0; i < comment_lines - 1; i++) {
        if (!fgets(line, sizeof(line), f)) {
            fclose(f);
            return -1;
        }
    }

    /* Read character definitions (ASCII 32-126) */
    for (int ascii = 32; ascii < 127; ascii++) {
        int max_width = 0;

        for (int row = 0; row < font_height; row++) {
            if (!fgets(line, sizeof(line), f)) {
                fclose(f);
                return -1;
            }

            /* Remove newline */
            char *nl = strchr(line, '\n');
            if (nl) *nl = '\0';

            /* Remove end markers (@ or @@) */
            int len = strlen(line);
            while (len > 0 && (line[len-1] == '@' || line[len-1] == '$')) {
                line[--len] = '\0';
            }

            /* Replace $ with space */
            for (int i = 0; i < len; i++) {
                if (line[i] == '$') line[i] = ' ';
            }

            strncpy(font_chars[ascii].lines[row], line, MAX_CHAR_WIDTH);
            font_chars[ascii].lines[row][MAX_CHAR_WIDTH] = '\0';

            if (len > max_width) {
                max_width = len;
            }
        }

        font_chars[ascii].width = max_width;
    }

    fclose(f);
    initialized = 1;
    return 0;
}

int ascii_render(const char *text, char **output_lines, int max_lines) {
    if (!initialized || !text || !output_lines) {
        return 0;
    }

    if (font_height > max_lines) {
        return 0;
    }

    /* Initialize output lines */
    for (int i = 0; i < font_height; i++) {
        output_lines[i][0] = '\0';
    }

    /* Render each character */
    int len = strlen(text);
    for (int i = 0; i < len; i++) {
        unsigned char c = (unsigned char)text[i];

        /* Convert to lowercase if uppercase */
        if (c >= 'A' && c <= 'Z') {
            c = c - 'A' + 'a';
        }

        /* Skip characters outside our range */
        if (c < 32 || c >= 127) {
            c = 32; /* Use space for unknown chars */
        }

        /* Append each line of the character */
        for (int row = 0; row < font_height; row++) {
            strncat(output_lines[row], font_chars[c].lines[row],
                    512 - strlen(output_lines[row]) - 1);
        }
    }

    return font_height;
}

void ascii_cleanup(void) {
    initialized = 0;
}
