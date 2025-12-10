#ifndef CONFIG_H
#define CONFIG_H

// Color configuration structure
typedef struct {
    char background[7];
    char border[7];
    char ascii_art[7];
    char ascii_highlight[7];
    char selector[7];
    char session[7];
    char password[7];
    char error[7];
    char info[7];
} ColorConfig;

// Load configuration from file
int config_load(const char *config_path, ColorConfig *config);

// Apply TTY color palette based on config
void config_apply_tty_colors(const ColorConfig *config);

// Get ANSI color code for a specific UI element
const char* config_get_ansi_color(const char *element);

#endif /* CONFIG_H */
