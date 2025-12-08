/*
 * figlet.h - Minimal vendored FIGlet font renderer
 *
 * Extracted from FIGlet 2.2.5
 * Copyright 1991-2012 FIGlet authors
 * Licensed under the BSD 3-Clause License
 *
 * This is a stripped-down version containing only:
 * - Font file loading for .flf files
 * - Proper character smushing with all FIGlet rules
 * - Simple rendering API
 */

#ifndef FIGLET_H
#define FIGLET_H

/* Initialize FIGlet with a font file */
int figlet_init(const char *font_path);

/* Render text to output lines */
int figlet_render(const char *text, char **output_lines, int max_lines);

/* Clean up FIGlet resources */
void figlet_cleanup(void);

#endif /* FIGLET_H */
