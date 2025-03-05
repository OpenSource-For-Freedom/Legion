// adding whitelist and trying to increase false positive prevention while scanning and loads
// this file has the GUI and deeper scan/log capability for deploying action vs just scanning
// needs api call and update heuristics model instead of reading files locally 
// Until we can get the api to read and the file write to action, this is just a scanning tool at the moment. 

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
#include <dlfcn.h>
#include <curl/curl.h>
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
#define API_ENDPOINT "http://localhost:5000/logs"

char *signatures[MAX_SIGNATURES];
int signature_count = 0;
char *whitelist[MAX_SIGNATURES];
int whitelist_count = 0;

// RUST 
typedef char* (*rust_scan_fn)(const char *);

// NASTY
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
           "  Legion - Linux Threat Signature Scanner | Version 1.3 \n"
           "---------------------------------------------------------\n"
           RESET "\n");
}

// ALERTING
void send_alert(const char *message) {
    CURL *curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, API_ENDPOINT);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, message);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
}

// LOAD WHTLST
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

// WHTLST
int is_whitelisted(const char *filename) {
    for (int i = 0; i < whitelist_count; i++) {
        if (strcmp(filename, whitelist[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

// RUST - scan
void run_rust_scanner(const char *filename) {
    void *handle = dlopen("./scanner.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "Error loading scanner.so\n");
        return;
    }

    rust_scan_fn rust_scan = (rust_scan_fn) dlsym(handle, "compute_sha256");
    if (!rust_scan) {
        fprintf(stderr, "Error loading Rust function\n");
        dlclose(handle);
        return;
    }

    char *result = rust_scan(filename);
    printf("[RUST SCANNER] %s -> Hash: %s\n", filename, result);
    send_alert(result);

    dlclose(handle);
}

// YARA (calls yara_integrations.c)
extern void scan_with_yara(const char *filename, int *score);

// MONITOR (calls ebpf_monitor.bpf.c)
void start_ebpf_monitor() {
    system("./ebpf_monitor");
}

// MONITOR
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
// NOTIFY 
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

                run_rust_scanner(full_path);
                scan_with_yara(full_path, &score);

                if (score > 1) {
                    printf(RED "[ALERT] Suspicious file detected: %s\n" RESET, full_path);
                    send_alert("[ALERT] Suspicious file detected.");
                }
            }
            i += EVENT_SIZE + event->len;
        }
    }

    inotify_rm_watch(inotify_fd, wd);
    close(inotify_fd);
    return NULL;
}

// MAIN
int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <signatures_file> <directory_to_monitor>\n", argv[0]);
        return 1;
    }

    print_ascii_banner();
    load_whitelist();

    pthread_t monitor_thread, ebpf_thread;

    if (pthread_create(&monitor_thread, NULL, monitor_directory, argv[2]) != 0) {
        perror("Error creating monitoring thread");
        return 1;
    }

    if (pthread_create(&ebpf_thread, NULL, (void *)start_ebpf_monitor, NULL) != 0) {
        perror("Error starting eBPF monitor");
        return 1;
    }

    pthread_join(monitor_thread, NULL);
    pthread_join(ebpf_thread, NULL);

    return 0;
}
