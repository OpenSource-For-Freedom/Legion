// adding whitelist and trying to increase false positive prevention while scanning and loads
// this file has the GUI and deeper scan/log capability for deploying action vs just scanning
// needs api call and update heuristics model instead of reading files locally 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <sys/inotify.h>
#include <libyara.h>
#include <time.h>
#include <syslog.h>

#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define RESET "\033[0m"

#define MAX_SIGNATURES 100
#define EVENT_SIZE (sizeof(struct inotify_event) + 256)
#define BUFFER_LEN (1024 * EVENT_SIZE)
#define LOG_FILE "/var/log/legion_scan.log"
#define WHITELIST_FILE "/etc/legion/whitelist.txt"
#define YARA_RULES_FILE "/etc/legion/rules.yar"

char *signatures[MAX_SIGNATURES];
int signature_count = 0;
char *whitelist[MAX_SIGNATURES];
int whitelist_count = 0;

// Prints ASCII Banner
void print_ascii_banner() {
    printf(RED "\n"
           "  @@@       @@@@@@@@   @@@@@@@@  @@@   @@@@@@   @@@  @@@  \n"
           "  @@@       @@@@@@@@  @@@@@@@@@  @@@  @@@@@@@@  @@@@ @@@  \n"
           "  @@!       @@!       !@@        @@!  @@!  @@@  @@!@!@@@  \n"
           "  !@!       !@!       !@!        !@!  !@!  @!@  !@!!@!@!  \n"
           "  @!!       @!!!:!    !@! @!@!@  !!@  @!@  !@!  @!@ !!@!  \n"
           "  !!!       !!!!!:    !!! !!@!!  !!!  !@!  !!!  !@!  !!!  \n"
           "  !!:       !!:       :!!   !!:  !!:  !!:  !!!  !!:  !!!  \n"
           "   :!:      :!:       :!:   !::  :!:  :!:  !:!  :!:  !:!  \n"
           "  :: ::::   :: ::::   ::: ::::   ::  ::::: ::   ::   ::  \n"
           " : :: : :  : :: ::    :: :: :   :     : :  :   ::    :   \n"
           RESET "\n"
           GREEN "---------------------------------------------------------\n"
           "  Legion - Linux Threat Signature Scanner | Version 1.2 \n"
           "---------------------------------------------------------\n"
           RESET "\n");
}

// Logs
void log_detection(const char *message) {
    openlog("LegionScanner", LOG_PID | LOG_CONS, LOG_USER);
    syslog(LOG_WARNING, "%s", message);
    closelog();
}

// Loads Whitelist
void load_whitelist() {
    FILE *file = fopen(WHITELIST_FILE, "r");
    if (!file) {
        perror("Error opening whitelist file");
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), file) && whitelist_count < MAX_SIGNATURES) {
        line[strcspn(line, "\n")] = '\0';
        whitelist[whitelist_count] = strdup(line);
        whitelist_count++;
    }
    fclose(file);
}

// Checks Whitelist
int is_whitelisted(const char *filename) {
    for (int i = 0; i < whitelist_count; i++) {
        if (strcmp(filename, whitelist[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

// Runs (es32 & Suricata) NEW add over clamv local scan 
int run_external_scanners(const char *filename) {
    char command[512];
    int score = 0;

    snprintf(command, sizeof(command), "es32 --scan %s --json > /dev/null 2>&1", filename);
    if (system(command) == 0) {
        score++;
        printf("[es32] Malware detected in %s\n", filename);
        log_detection("[es32 DETECTION] Malware found.");
    }

    snprintf(command, sizeof(command), "suricata -r %s > /dev/null 2>&1", filename);
    if (system(command) == 0) {
        score++;
        printf("[Suricata] Threat detected in %s\n", filename);
        log_detection("[Suricata DETECTION] Threat found.");
    }

    return score;
}

// YARA Scan
void scan_with_yara(const char *filename, int *score) {
    if (is_whitelisted(filename)) {
        printf("[INFO] Skipping whitelisted file: %s\n", filename);
        return;
    }

    YR_RULES *rules;
    YR_COMPILER *compiler;

    if (yr_initialize() != ERROR_SUCCESS) {
        perror("Failed to initialize YARA");
        return;
    }

    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        perror("Failed to create YARA compiler");
        yr_finalize();
        return;
    }

    FILE *rules_file = fopen(YARA_RULES_FILE, "r");
    if (!rules_file) {
        perror("Error opening YARA rules file");
        yr_compiler_destroy(compiler);
        yr_finalize();
        return;
    }

    if (yr_compiler_add_file(compiler, rules_file, NULL, "main") != ERROR_SUCCESS) {
        perror("Error compiling YARA rules");
        fclose(rules_file);
        yr_compiler_destroy(compiler);
        yr_finalize();
        return;
    }

    fclose(rules_file);
    if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {
        perror("Error getting YARA rules");
        yr_compiler_destroy(compiler);
        yr_finalize();
        return;
    }

    if (yr_rules_scan_file(rules, filename, 0, NULL, NULL, 0) == ERROR_SUCCESS) {
        printf("[YARA] Potential malware found in %s\n", filename);
        log_detection("[YARA DETECTION] Potential malware found.");
        (*score)++;
    }

    yr_rules_destroy(rules);
    yr_compiler_destroy(compiler);
    yr_finalize();
}

// Monitors 
void *monitor_directory(void *arg) {
    char *dir = (char *)arg;
    int inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        perror("Error initializing inotify");
        return NULL;
    }

    int wd = inotify_add_watch(inotify_fd, dir, IN_CREATE | IN_MODIFY);
    if (wd < 0) {
        perror("Error adding watch");
        close(inotify_fd);
        return NULL;
    }

    char buffer[BUFFER_LEN];
    while (1) {
        int length = read(inotify_fd, buffer, BUFFER_LEN);
        if (length < 0) {
            perror("Error reading inotify events");
            continue;
        }

        for (int i = 0; i < length;) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            if (event->len && (event->mask & (IN_CREATE | IN_MODIFY))) {
                char full_path[1024];
                snprintf(full_path, sizeof(full_path), "%s/%s", dir, event->name);

                if (is_whitelisted(full_path)) {
                    printf("[INFO] Skipping whitelisted file: %s\n", full_path);
                    continue;
                }

                printf("[REAL-TIME] Detected change in %s, scanning...\n", full_path);
                int score = 0;
                scan_with_yara(full_path, &score);
                score += run_external_scanners(full_path);

                if (score > 1) {
                    printf(RED "[ALERT] Suspicious file detected: %s\n" RESET, full_path);
                }
            }
            i += EVENT_SIZE + event->len;
        }
    }

    inotify_rm_watch(inotify_fd, wd);
    close(inotify_fd);
    return NULL;
}

// Main Function
int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <signatures_file> <directory_to_monitor>\n", argv[0]);
        return 1;
    }

    print_ascii_banner();
    load_whitelist();

    pthread_t monitor_thread;
    if (pthread_create(&monitor_thread, NULL, monitor_directory, argv[2]) != 0) {
        perror("Error creating monitoring thread");
        return 1;
    }

    pthread_join(monitor_thread, NULL);
    return 0;
}