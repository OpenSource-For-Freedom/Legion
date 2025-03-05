// integration scanner using yara and clamv db
#include <stdio.h>
#include <stdlib.h>
#include <libyara.h>

#define YARA_RULES_FILE "/etc/legion/rules.yar"
// compile 
void scan_with_yara(const char *filename) {
    YR_RULES *rules;
    YR_COMPILER *compiler;

    if (yr_initialize() != ERROR_SUCCESS) return;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) return;
// file
    FILE *rules_file = fopen(YARA_RULES_FILE, "r");
    if (!rules_file) return;

    yr_compiler_add_file(compiler, rules_file, NULL, "main");
    fclose(rules_file);
    yr_compiler_get_rules(compiler, &rules);

    if (yr_rules_scan_file(rules, filename, 0, NULL, NULL, 0) == ERROR_SUCCESS)
        printf("[YARA] Threat detected in %s\n", filename);
// destroy 
    yr_rules_destroy(rules);
    yr_compiler_destroy(compiler);
    yr_finalize();
}