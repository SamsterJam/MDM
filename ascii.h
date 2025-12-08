/*
 * ascii.h - FIGlet font rendering interface
 * Part of MDM (Minimal Display Manager)
 */

#ifndef ASCII_H
#define ASCII_H

#define MAX_CHAR_HEIGHT 10
#define MAX_CHAR_WIDTH 20

/* Initialize the ASCII art font from file */
int ascii_init(const char *font_path);

/* Render text using ASCII art font, returns number of lines rendered */
int ascii_render(const char *text, char **output_lines, int max_lines);

/* Free ASCII art resources */
void ascii_cleanup(void);

#endif /* ASCII_H */
