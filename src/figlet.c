/*
 * figlet.c - Minimal vendored FIGlet font renderer
 *
 * Extracted and simplified from FIGlet 2.2.5
 * Copyright 1991-2012 Glenn Chappell, Ian Chai, John Cowan, Christiaan Keet, Claudio Matsuoka
 * Licensed under the BSD 3-Clause License
 *
 * Simplifications in this version:
 * - Removed: compression support, UTF-8/multibyte, control files, command-line parsing
 * - Removed: right-to-left rendering, multiple justification modes
 * - Kept: Full FIGlet smushing algorithm with all 6 rules
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "figlet.h"

#define MAXLEN 255

/* Smushing mode flags (from original FIGlet) */
#define SM_SMUSH 128
#define SM_KERN 64
#define SM_EQUAL 1
#define SM_LOWLINE 2
#define SM_HIERARCHY 4
#define SM_PAIR 8
#define SM_BIGX 16
#define SM_HARDBLANK 32

/* Character node for linked list */
typedef struct fc {
    int ord;             /* ASCII code */
    char **thechar;      /* Array of charheight strings */
    struct fc *next;
} fcharnode;

/* Font globals */
static fcharnode *fcharlist = NULL;
static char hardblank = '$';
static int charheight = 0;
static int smushmode = 0;
static int initialized = 0;

/* Current rendering state */
static char **currchar = NULL;
static int currcharwidth = 0;
static int previouscharwidth = 0;

static char **outputline = NULL;
static int outlinelen = 0;
static int outlinelenlimit = 512;

/* Memory allocation with error checking */
static void *myalloc(size_t size) {
    void *ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "figlet: Out of memory\n");
        exit(1);
    }
    return ptr;
}

/*
 * readfontchar - Read one character definition from font file
 */
static void readfontchar(FILE *file, int theord) {
    int row, k;
    char templine[MAXLEN + 1];
    char endchar;
    fcharnode *fclsave;

    fclsave = fcharlist;
    fcharlist = (fcharnode *)myalloc(sizeof(fcharnode));
    fcharlist->ord = theord;
    fcharlist->thechar = (char **)myalloc(sizeof(char *) * charheight);
    fcharlist->next = fclsave;

    for (row = 0; row < charheight; row++) {
        if (fgets(templine, MAXLEN, file) == NULL) {
            templine[0] = '\0';
        }

        /* Remove trailing whitespace */
        k = strlen(templine) - 1;
        while (k >= 0 && isspace((unsigned char)templine[k])) {
            k--;
        }

        /* Remove end markers (@ or @@) */
        if (k >= 0) {
            endchar = templine[k];
            while (k >= 0 && templine[k] == endchar) {
                k--;
            }
        }

        templine[k + 1] = '\0';
        size_t len = strlen(templine) + 1;
        fcharlist->thechar[row] = (char *)myalloc(len);
        memcpy(fcharlist->thechar[row], templine, len);
    }
}

/*
 * readfont - Load font file and parse all character definitions
 */
static int readfont(const char *font_path) {
    FILE *fontfile;
    char fileline[MAXLEN + 1];
    char magicnum[5];
    int maxlen, cmtlines, smush, smush2, ffright2left;
    int numsread, i, row;
    int theord;

    fontfile = fopen(font_path, "r");
    if (!fontfile) {
        return -1;
    }

    /* Read magic number */
    if (fgets(magicnum, 5, fontfile) == NULL) {
        fclose(fontfile);
        return -1;
    }

    /* Read header line */
    if (fgets(fileline, MAXLEN, fontfile) == NULL) {
        fclose(fontfile);
        return -1;
    }

    numsread = sscanf(fileline, "%*c%c %d %*d %d %d %d %d %d",
                      &hardblank, &charheight, &maxlen, &smush, &cmtlines,
                      &ffright2left, &smush2);

    if (strncmp(magicnum, "flf2", 4) != 0 || numsread < 5) {
        fclose(fontfile);
        return -1;
    }

    /* Skip comment lines */
    for (i = 1; i <= cmtlines; i++) {
        if (fgets(fileline, MAXLEN, fontfile) == NULL) {
            break;
        }
    }

    /* Decode smush mode */
    if (numsread < 7) {
        if (smush == 0) {
            smush2 = SM_KERN;
        } else if (smush < 0) {
            smush2 = 0;
        } else {
            smush2 = (smush & 31) | SM_SMUSH;
        }
    }

    smushmode = smush2;

    /* Allocate "missing" character (ord=0) */
    fcharlist = (fcharnode *)myalloc(sizeof(fcharnode));
    fcharlist->ord = 0;
    fcharlist->thechar = (char **)myalloc(sizeof(char *) * charheight);
    fcharlist->next = NULL;
    for (row = 0; row < charheight; row++) {
        fcharlist->thechar[row] = (char *)myalloc(1);
        fcharlist->thechar[row][0] = '\0';
    }

    /* Read ASCII characters 32-126 */
    for (theord = ' '; theord <= '~'; theord++) {
        readfontchar(fontfile, theord);
    }

    /* German characters (optional, skip if not present) */
    static int deutsch[7] = {196, 214, 220, 228, 246, 252, 223};
    for (i = 0; i < 7; i++) {
        readfontchar(fontfile, deutsch[i]);
    }

    fclose(fontfile);
    return 0;
}

/*
 * getletter - Look up character in font, set currchar
 */
static void getletter(int c) {
    fcharnode *charptr;

    /* Search for character */
    for (charptr = fcharlist; charptr != NULL && charptr->ord != c; charptr = charptr->next)
        ;

    if (charptr != NULL) {
        currchar = charptr->thechar;
    } else {
        /* Use "missing" character (ord=0) */
        for (charptr = fcharlist; charptr != NULL && charptr->ord != 0; charptr = charptr->next)
            ;
        if (charptr != NULL) {
            currchar = charptr->thechar;
        } else {
            /* Font corrupted or empty - use safe fallback */
            static char *emptychars[1] = {""};
            currchar = emptychars;
        }
    }

    previouscharwidth = currcharwidth;
    currcharwidth = (currchar && currchar[0]) ? strlen(currchar[0]) : 0;
}

/*
 * smushem - Apply FIGlet smushing rules to two characters
 *
 * Returns the smushed character, or '\0' if no smushing can be done.
 * This is the original FIGlet algorithm.
 */
static char smushem(char lch, char rch) {
    /* Rule: blanks get replaced */
    if (lch == ' ') return rch;
    if (rch == ' ') return lch;

    /* Disallow overlapping if either character has width < 2 */
    if (previouscharwidth < 2 || currcharwidth < 2) {
        return '\0';
    }

    /* If smushing is disabled, return '\0' (kerning only) */
    if ((smushmode & SM_SMUSH) == 0) {
        return '\0';
    }

    /* Universal overlapping (no specific rules, just smush) */
    if ((smushmode & 63) == 0) {
        if (lch == hardblank) return rch;
        if (rch == hardblank) return lch;
        return rch;
    }

    /* Rule 6: Hardblank smushing */
    if (smushmode & SM_HARDBLANK) {
        if (lch == hardblank && rch == hardblank) {
            return lch;
        }
    }

    /* Don't smush hardblanks using rules below */
    if (lch == hardblank || rch == hardblank) {
        return '\0';
    }

    /* Rule 1: Equal character smushing */
    if (smushmode & SM_EQUAL) {
        if (lch == rch) {
            return lch;
        }
    }

    /* Rule 2: Underscore smushing */
    if (smushmode & SM_LOWLINE) {
        if (lch == '_' && strchr("|/\\[]{}()<>", rch)) return rch;
        if (rch == '_' && strchr("|/\\[]{}()<>", lch)) return lch;
    }

    /* Rule 3: Hierarchy smushing */
    if (smushmode & SM_HIERARCHY) {
        if (lch == '|' && strchr("/\\[]{}()<>", rch)) return rch;
        if (rch == '|' && strchr("/\\[]{}()<>", lch)) return lch;
        if (strchr("/\\", lch) && strchr("[]{}()<>", rch)) return rch;
        if (strchr("/\\", rch) && strchr("[]{}()<>", lch)) return lch;
        if (strchr("[]", lch) && strchr("{}()<>", rch)) return rch;
        if (strchr("[]", rch) && strchr("{}()<>", lch)) return lch;
        if (strchr("{}", lch) && strchr("()<>", rch)) return rch;
        if (strchr("{}", rch) && strchr("()<>", lch)) return lch;
        if (strchr("()", lch) && strchr("<>", rch)) return rch;
        if (strchr("()", rch) && strchr("<>", lch)) return lch;
    }

    /* Rule 4: Opposite pair smushing */
    if (smushmode & SM_PAIR) {
        if (lch == '[' && rch == ']') return '|';
        if (rch == '[' && lch == ']') return '|';
        if (lch == '{' && rch == '}') return '|';
        if (rch == '{' && lch == '}') return '|';
        if (lch == '(' && rch == ')') return '|';
        if (rch == '(' && lch == ')') return '|';
    }

    /* Rule 5: Big X smushing */
    if (smushmode & SM_BIGX) {
        if (lch == '/' && rch == '\\') return '|';
        if (rch == '/' && lch == '\\') return 'Y';
        if (lch == '>' && rch == '<') return 'X';
    }

    return '\0';
}

/*
 * smushamt - Calculate maximum smush amount for current character
 *
 * Returns the number of columns that can be overlapped.
 */
static int smushamt(void) {
    int maxsmush, amt;
    int row, linebd, charbd;
    char ch1, ch2;

    if ((smushmode & (SM_SMUSH | SM_KERN)) == 0) {
        return 0;
    }

    maxsmush = currcharwidth;

    for (row = 0; row < charheight; row++) {
        /* Find rightmost non-blank in output line */
        linebd = strlen(outputline[row]);
        while (linebd > 0 && (outputline[row][linebd] == '\0' || outputline[row][linebd] == ' ')) {
            linebd--;
        }

        /* Find leftmost non-blank in current char */
        charbd = 0;
        while (currchar[row][charbd] == ' ') {
            charbd++;
        }

        amt = charbd + outlinelen - 1 - linebd;

        /* Check if we can smush these two characters */
        ch1 = (linebd >= 0 && linebd < (int)strlen(outputline[row])) ? outputline[row][linebd] : '\0';
        ch2 = currchar[row][charbd];

        if (!ch1 || ch1 == ' ') {
            amt++;
        } else if (ch2) {
            if (smushem(ch1, ch2) != '\0') {
                amt++;
            }
        }

        if (amt < maxsmush) {
            maxsmush = amt;
        }
    }

    return maxsmush;
}

/*
 * addchar - Add a character to the output line with smushing
 *
 * Returns 1 on success, 0 if character doesn't fit.
 */
static int addchar(int c) {
    int smushamount, row, k, column;

    getletter(c);
    smushamount = smushamt();

    if (outlinelen + currcharwidth - smushamount > outlinelenlimit) {
        return 0;
    }

    /* Perform smushing */
    for (row = 0; row < charheight; row++) {
        /* Apply smushing at overlap points */
        for (k = 0; k < smushamount; k++) {
            column = outlinelen - smushamount + k;
            if (column >= 0 && column < outlinelenlimit) {
                char smushed = smushem(outputline[row][column], currchar[row][k]);
                if (smushed != '\0') {
                    outputline[row][column] = smushed;
                }
            }
        }

        /* Append the rest of the character */
        strncat(outputline[row], currchar[row] + smushamount,
                outlinelenlimit - strlen(outputline[row]));
    }

    outlinelen = strlen(outputline[0]);
    return 1;
}

/*
 * Public API
 */

int figlet_init(const char *font_path) {
    if (initialized) {
        figlet_cleanup();
    }

    if (readfont(font_path) != 0) {
        return -1;
    }

    /* Allocate output lines */
    outputline = (char **)myalloc(sizeof(char *) * charheight);
    for (int i = 0; i < charheight; i++) {
        outputline[i] = (char *)myalloc(outlinelenlimit + 1);
        outputline[i][0] = '\0';
    }

    initialized = 1;
    return 0;
}

int figlet_render(const char *text, char **output_lines, int max_lines) {
    int i, len;

    if (!initialized || !text || !output_lines) {
        return 0;
    }

    if (charheight > max_lines) {
        return 0;
    }

    /* Clear output lines */
    for (i = 0; i < charheight; i++) {
        outputline[i][0] = '\0';
    }
    outlinelen = 0;

    /* Render each character */
    len = strlen(text);
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)text[i];

        /* Skip non-printable characters */
        if (c < 32 || c >= 127) {
            c = ' ';
        }

        if (!addchar(c)) {
            break;  /* Line full */
        }
    }

    /* Trim blank lines from top and bottom */
    int first_line = 0;
    int last_line = charheight - 1;

    /* Find first non-empty line */
    for (i = 0; i < charheight; i++) {
        int is_empty = 1;
        for (int j = 0; outputline[i][j]; j++) {
            if (outputline[i][j] != ' ' && outputline[i][j] != hardblank) {
                is_empty = 0;
                break;
            }
        }
        if (!is_empty) {
            first_line = i;
            break;
        }
    }

    /* Find last non-empty line */
    for (i = charheight - 1; i >= 0; i--) {
        int is_empty = 1;
        for (int j = 0; outputline[i][j]; j++) {
            if (outputline[i][j] != ' ' && outputline[i][j] != hardblank) {
                is_empty = 0;
                break;
            }
        }
        if (!is_empty) {
            last_line = i;
            break;
        }
    }

    /* Copy output, replacing hardblanks with spaces */
    int output_height = last_line - first_line + 1;
    for (i = 0; i < output_height; i++) {
        strncpy(output_lines[i], outputline[first_line + i], 511);
        output_lines[i][511] = '\0';

        /* Replace hardblanks with spaces */
        for (int j = 0; output_lines[i][j]; j++) {
            if (output_lines[i][j] == hardblank) {
                output_lines[i][j] = ' ';
            }
        }
    }

    /* Trim leading spaces common to all lines */
    int min_leading = 512;
    for (i = 0; i < output_height; i++) {
        int leading = 0;
        while (output_lines[i][leading] == ' ') {
            leading++;
        }
        if (output_lines[i][leading] != '\0' && leading < min_leading) {
            min_leading = leading;
        }
    }

    if (min_leading > 0 && min_leading < 512) {
        for (i = 0; i < output_height; i++) {
            if (strlen(output_lines[i]) > (size_t)min_leading) {
                memmove(output_lines[i], output_lines[i] + min_leading,
                        strlen(output_lines[i]) - min_leading + 1);
            }
        }
    }

    return output_height;
}

void figlet_cleanup(void) {
    fcharnode *ptr, *next;

    if (!initialized) {
        return;
    }

    /* Free font characters */
    for (ptr = fcharlist; ptr != NULL; ptr = next) {
        next = ptr->next;
        for (int i = 0; i < charheight; i++) {
            free(ptr->thechar[i]);
        }
        free(ptr->thechar);
        free(ptr);
    }

    /* Free output lines */
    if (outputline) {
        for (int i = 0; i < charheight; i++) {
            free(outputline[i]);
        }
        free(outputline);
        outputline = NULL;
    }

    fcharlist = NULL;
    initialized = 0;
}
