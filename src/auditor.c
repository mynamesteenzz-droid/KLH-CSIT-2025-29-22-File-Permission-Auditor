  GNU nano 7.2                                                                                                                                                                                                                                                                                                                                                        auditor.c *
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define INPUT_SIZE 4096

typedef struct {
    char *path;
    mode_t mode;
    uid_t uid;
    gid_t gid;
    int selectable;
} ScanEntry;

static char scan_path[PATH_MAX];
static ScanEntry *entries;
static size_t entry_count;
static size_t entry_capacity;
static size_t total_count, safe_count, warning_count, critical_count;
static int scan_had_errors;
static int scan_performed;

static void permission_string(mode_t mode, char out[10]) {
    out[0] = (mode & S_IRUSR) ? 'r' : '-'; out[1] = (mode & S_IWUSR) ? 'w' : '-'; out[2] = (mode & S_IXUSR) ? 'x' : '-';
    out[3] = (mode & S_IRGRP) ? 'r' : '-'; out[4] = (mode & S_IWGRP) ? 'w' : '-'; out[5] = (mode & S_IXGRP) ? 'x' : '-';
    out[6] = (mode & S_IROTH) ? 'r' : '-'; out[7] = (mode & S_IWOTH) ? 'w' : '-'; out[8] = (mode & S_IXOTH) ? 'x' : '-'; out[9] = '\0';
}

static const char *risk_level(mode_t mode) {
    if (mode & S_IWOTH) return "CRITICAL";
    if (mode & S_IWGRP) return "WARNING";
    return "SAFE";
}

static int add_entry(const char *path, const struct stat *st) {
    if (entry_count == entry_capacity) {
        size_t next = entry_capacity ? entry_capacity * 2 : 64;
        ScanEntry *grown = realloc(entries, next * sizeof(*entries));
        if (!grown) { fprintf(stderr, "Cannot store scan results: %s\n", strerror(errno)); scan_had_errors = 1; return -1; }
        entries = grown; entry_capacity = next;
    }
    entries[entry_count].path = strdup(path);
    if (!entries[entry_count].path) { fprintf(stderr, "Cannot store scan path: %s\n", strerror(errno)); scan_had_errors = 1; return -1; }
    entries[entry_count].mode = st->st_mode;
    entries[entry_count].uid = st->st_uid;
    entries[entry_count].gid = st->st_gid;
    entries[entry_count].selectable = !S_ISLNK(st->st_mode);
    entry_count++;
    return 0;
}

static const char *entry_type(mode_t mode) {
    if (S_ISDIR(mode)) return "Directory";
    if (S_ISREG(mode)) return "File";
    if (S_ISLNK(mode)) return "Symbolic link";
    return "Other";
}

static void print_entry(const char *path, mode_t mode, uid_t uid, gid_t gid) {
    char perms[10];
    permission_string(mode, perms);
    puts("\n--------------------------------------------");
    printf("Path       : %s\nType       : %s\nPermission : %s\nRisk       : %s\nOwner UID  : %lu\nGroup GID  : %lu\n",
           path, entry_type(mode), perms, risk_level(mode), (unsigned long)uid, (unsigned long)gid);
    puts("--------------------------------------------");
}

static void record_entry(const char *path, const struct stat *st) {
    print_entry(path, st->st_mode, st->st_uid, st->st_gid);
    total_count++;
    if (st->st_mode & S_IWOTH) critical_count++;
    else if (st->st_mode & S_IWGRP) warning_count++;
    else safe_count++;
    (void)add_entry(path, st);
}

static void scan_directory(const char *path) {
    DIR *dir = opendir(path);
    if (!dir) { fprintf(stderr, "Cannot access directory: %s\nReason: %s\n", path, strerror(errno)); scan_had_errors = 1; return; }
    errno = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) { errno = 0; continue; }
        char full[PATH_MAX];
        int n = snprintf(full, sizeof(full), "%s%s%s", path, (path[0] && path[strlen(path)-1] == '/') ? "" : "/", ent->d_name);
        if (n < 0 || (size_t)n >= sizeof(full)) { fprintf(stderr, "Path too long under %s\n", path); scan_had_errors = 1; errno = 0; continue; }
        struct stat st;
        if (lstat(full, &st) != 0) { fprintf(stderr, "Cannot inspect %s: %s\n", full, strerror(errno)); scan_had_errors = 1; errno = 0; continue; }
        record_entry(full, &st);
        /* lstat identifies links; recurse only into actual directories. */
        if (S_ISDIR(st.st_mode)) scan_directory(full);
        errno = 0;
    }
    if (errno != 0) { fprintf(stderr, "Error reading directory %s: %s\n", path, strerror(errno)); scan_had_errors = 1; }
    if (closedir(dir) != 0) { fprintf(stderr, "Error closing directory %s: %s\n", path, strerror(errno)); scan_had_errors = 1; }
}

static void free_entries(void) {
    for (size_t i = 0; i < entry_count; i++) free(entries[i].path);
    free(entries); entries = NULL; entry_count = entry_capacity = 0;
}

static int read_line(const char *prompt, char *buf, size_t size) {
    fputs(prompt, stdout); fflush(stdout);
    if (!fgets(buf, (int)size, stdin)) return 0;
    size_t len = strlen(buf);
    if (len && buf[len-1] == '\n') buf[--len] = '\0';
    else if (!feof(stdin)) { int c; while ((c = getchar()) != '\n' && c != EOF) {} fprintf(stderr, "Input too long.\n"); return -1; }
    if (len && buf[len-1] == '\r') buf[len-1] = '\0';
    return 1;
}

#define SEARCH_MAX_DEPTH 9
#define SEARCH_MAX_DIRS 2000

typedef struct {
    char **items;
    size_t count;
    size_t capacity;
} StringList;

static StringList search_matches;
static size_t searched_directories;
static size_t search_directory_limit;
static unsigned search_depth_limit;
static int search_limited;

static int list_add_unique(StringList *list, const char *value) {
    for (size_t i = 0; i < list->count; i++)
        if (strcmp(list->items[i], value) == 0) return 1;
    if (list->count == list->capacity) {
        size_t next = list->capacity ? list->capacity * 2 : 32;
        char **grown = realloc(list->items, next * sizeof(*list->items));
        if (!grown) return -1;
        list->items = grown;
        list->capacity = next;
    }
    list->items[list->count] = strdup(value);
    if (!list->items[list->count]) return -1;
    list->count++;
    return 0;
}

static void list_clear(StringList *list) {
    for (size_t i = 0; i < list->count; i++) free(list->items[i]);
    free(list->items);
    list->items = NULL;
    list->count = list->capacity = 0;
}

static int accessible_directory(const char *path, char resolved[PATH_MAX]) {
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) return 0;
    DIR *dir = opendir(path);
    if (!dir) return 0;
    int close_error = closedir(dir);
    if (close_error != 0 || !realpath(path, resolved)) return 0;
    return 1;
}

static void remember_match(const char *path) {
    char resolved[PATH_MAX];
    if (!accessible_directory(path, resolved)) return;
    if (list_add_unique(&search_matches, resolved) < 0)
        fprintf(stderr, "Unable to store directory search results: %s\n", strerror(errno));
}

static void search_tree(const char *path, const char *name, unsigned depth) {
    if (depth > search_depth_limit || searched_directories >= search_directory_limit) {
        search_limited = 1;
        return;
    }
    char resolved[PATH_MAX];
    if (!realpath(path, resolved)) return;
    DIR *dir = opendir(resolved);
    if (!dir) return;
    searched_directories++;
    const char *base = strrchr(resolved, '/');
    base = base ? base + 1 : resolved;
    if (strcmp(base, name) == 0) remember_match(resolved);

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        char child[PATH_MAX];
        int n = snprintf(child, sizeof(child), "%s%s%s", resolved,
                         resolved[strlen(resolved) - 1] == '/' ? "" : "/", entry->d_name);
        if (n < 0 || (size_t)n >= sizeof(child)) continue;
        struct stat st;
        if (lstat(child, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        if (strcmp(entry->d_name, name) == 0) remember_match(child);
        int prune = strcmp(entry->d_name, "AppData") == 0 ||
                    strcmp(entry->d_name, "Application Data") == 0 ||
                    strcmp(entry->d_name, ".cache") == 0 ||
                    strcmp(entry->d_name, ".git") == 0 ||
                    strcmp(entry->d_name, "node_modules") == 0 ||
                    strcmp(entry->d_name, "WindowsApps") == 0 ||
                    strcmp(entry->d_name, "System Volume Information") == 0 ||
                    strcmp(entry->d_name, "Default") == 0 ||
                    strcmp(entry->d_name, "Default User") == 0 ||
                    strcmp(entry->d_name, "All Users") == 0 ||
                    strcmp(entry->d_name, "Public") == 0;
        if (!prune && depth < search_depth_limit && searched_directories < search_directory_limit)
            search_tree(child, name, depth + 1);
        else if (!prune)
            search_limited = 1;
    }
    closedir(dir);
}

static void print_directory_found(const char *search_name) {
    puts("============================================\n           DIRECTORY FOUND\n============================================");
    if (search_name) printf("Search name : %s\n", search_name);
    printf("Actual path : %s\n============================================\n", scan_path);
}

static int get_valid_directory(void) {
    char input[INPUT_SIZE];
    for (;;) {
        int rc = read_line("Enter directory to scan: ", input, sizeof(input));
        if (rc == 0) return 0;
        if (rc < 0) continue;
        if (input[0] == '\0') { puts("ERROR\nDirectory path cannot be empty."); continue; }

        struct stat st;
        if (stat(input, &st) == 0) {
            if (!S_ISDIR(st.st_mode)) {
                printf("============================================\n                  ERROR\n============================================\nThe path is not a directory.\nPath: %s\n============================================\n", input);
                continue;
            }
            DIR *dir = opendir(input);
            if (!dir) {
                printf("============================================\n                  ERROR\n============================================\nCannot access directory.\nReason: %s\nPath: %s\n============================================\n", strerror(errno), input);
                continue;
            }
            closedir(dir);
            if (!realpath(input, scan_path)) {
                printf("Cannot resolve directory path %s: %s\n", input, strerror(errno));
                continue;
            }
            print_directory_found(NULL);
            return 1;
        }

        int path_error = errno;
        int simple_name = input[0] != '/' && strchr(input, '/') == NULL &&
                          strcmp(input, ".") != 0 && strcmp(input, "..") != 0;
        if (!simple_name || (path_error != ENOENT && path_error != ENOTDIR)) {
            if (path_error == ENOENT || path_error == ENOTDIR)
                printf("============================================\n                  ERROR\n============================================\nDirectory does not exist.\nPath: %s\n============================================\n", input);
            else
                printf("============================================\n                  ERROR\n============================================\nCannot access directory.\nReason: %s\nPath: %s\n============================================\n", strerror(path_error), input);
            continue;
        }

        puts("Searching accessible locations for a directory with that name...");
        list_clear(&search_matches);
        search_limited = 0;
        static const char *linux_roots[] = { ".", "/root", "/home" };
        for (size_t i = 0; i < sizeof(linux_roots) / sizeof(linux_roots[0]); i++) {
            searched_directories = 0;
            search_directory_limit = SEARCH_MAX_DIRS;
            search_depth_limit = SEARCH_MAX_DEPTH;
            search_tree(linux_roots[i], input, 0);
        }
        /* Search the mounted Windows user profiles only when Linux roots have no match. */
        if (search_matches.count == 0) {
            searched_directories = 0;
            search_directory_limit = 250;
            search_depth_limit = 4;
            search_tree("/mnt/c/Users", input, 0);
        }

        if (search_matches.count == 0) {
            printf("============================================\n                  ERROR\n============================================\nNo accessible directory named '%s' was found.\n", input);
            if (search_limited)
                puts("The bounded search limit was reached; provide a full path or search a narrower location.");
            puts("============================================");
            list_clear(&search_matches);
            continue;
        }

        size_t selected = 0;
        if (search_matches.count > 1 || search_limited) {
            if (search_matches.count > 1)
                puts("============================================\n          MULTIPLE DIRECTORIES FOUND\n============================================");
            else
                puts("============================================\n       SEARCH LIMIT REACHED\nMatches found so far (more may exist):\n============================================");
            for (size_t i = 0; i < search_matches.count; i++)
                printf("%zu. %s\n", i + 1, search_matches.items[i]);
            char choice[64];
            int choice_rc = read_line("Enter the number to scan (0 to cancel): ", choice, sizeof(choice));
            char *choice_end;
            long number = choice_rc > 0 ? strtol(choice, &choice_end, 10) : -1;
            if (choice_rc <= 0 || choice_end == choice || *choice_end != '\0' ||
                number < 0 || (size_t)number > search_matches.count) {
                puts("Invalid selection.");
                list_clear(&search_matches);
                continue;
            }
            if (number == 0) {
                puts("Directory selection cancelled.");
                list_clear(&search_matches);
                continue;
            }
            selected = (size_t)number - 1;
            strcpy(scan_path, search_matches.items[selected]);
        } else {
            strcpy(scan_path, search_matches.items[0]);
        }
        /* Revalidate the chosen match immediately before accepting it. */
        char confirmed[PATH_MAX];
        if (!accessible_directory(scan_path, confirmed)) {
            printf("Directory is no longer accessible: %s\n", scan_path);
            list_clear(&search_matches);
            continue;
        }
        strcpy(scan_path, confirmed);
        print_directory_found(input);
        if (search_limited) puts("Note: the name search reached its safety limit; additional matches may exist.");
        list_clear(&search_matches);
        return 1;
    }
}
static void scan_selected_directory(void) {
    free_entries(); total_count = safe_count = warning_count = critical_count = 0; scan_had_errors = 0; scan_performed = 1;
    puts("\n--------------------------------------------\n              DIRECTORY SCAN\n--------------------------------------------");
    printf("Scanning current filesystem contents under: %s\n", scan_path);
    /* Revalidate each time; selection can become invalid while the app is open. */
    struct stat st;
    if (stat(scan_path, &st) != 0) { printf("Cannot access selected directory: %s\n", strerror(errno)); scan_had_errors = 1; }
    else if (!S_ISDIR(st.st_mode)) { puts("Selected path is no longer a directory."); scan_had_errors = 1; }
    else scan_directory(scan_path);
    printf("\nScan %s.\nTotal Files : %zu\nSafe        : %zu\nWarning     : %zu\nCritical    : %zu\n",
           scan_had_errors ? "completed with errors" : "completed successfully", total_count, safe_count, warning_count, critical_count);
    puts("--------------------------------------------");
}

static void show_report(void) {
    if (!scan_performed) { puts("No scan has been performed yet."); return; }
    puts("\n============================================\n                SCAN REPORT\n============================================");
    printf("Directory   : %s\nTotal Files : %zu\nSafe        : %zu\nWarning     : %zu\nCritical    : %zu\nScan status : %s\n",
           scan_path, total_count, safe_count, warning_count, critical_count, scan_had_errors ? "completed with errors" : "complete");
    puts("============================================");
}

static void filter_results(void) {
    if (!scan_performed) { puts("No scan results available. Scan a directory first."); return; }
    puts("\n============================================\n              FILTER RESULTS\n============================================\n1. Show All\n2. Show Safe\n3. Show Warning\n4. Show Critical\n============================================");
    char input[64]; int rc = read_line("Enter filter: ", input, sizeof(input));
    if (rc <= 0) return;
    char *end; errno = 0; long choice = strtol(input, &end, 10);
    if (errno || end == input || *end || choice < 1 || choice > 4) { puts("Invalid filter."); return; }
    size_t shown = 0;
    for (size_t i = 0; i < entry_count; i++) {
        const char *risk = risk_level(entries[i].mode);
        if (choice == 2 && strcmp(risk, "SAFE") != 0) continue;
        if (choice == 3 && strcmp(risk, "WARNING") != 0) continue;
        if (choice == 4 && strcmp(risk, "CRITICAL") != 0) continue;
        print_entry(entries[i].path, entries[i].mode, entries[i].uid, entries[i].gid);
        shown++;
    }
    printf("\nEntries shown: %zu\n", shown);
}

static void fix_permission(void) {
    if (!scan_performed || entry_count == 0) { puts("No scanned entries available. Scan a directory first."); return; }
    puts("\nScanned entries (symbolic links are not eligible for chmod):");
    size_t shown = 0;
    for (size_t i = 0; i < entry_count; i++) {
        if (!entries[i].selectable) continue;
        char p[10]; permission_string(entries[i].mode, p);
            printf("%zu. %s (%s, %s, UID %lu, GID %lu)\n", ++shown, entries[i].path, p,
               entry_type(entries[i].mode), (unsigned long)entries[i].uid, (unsigned long)entries[i].gid);
    }
    if (!shown) { puts("No eligible entries."); return; }
    char input[128]; char *end; errno = 0;
    int rc = read_line("Enter entry number: ", input, sizeof(input)); if (rc <= 0) return;
    long pick = strtol(input, &end, 10);
    if (errno || end == input || *end || pick < 1 || (size_t)pick > shown) { puts("Invalid entry number."); return; }
    size_t idx = 0;
    for (size_t i = 0; i < entry_count; i++) if (entries[i].selectable && ++idx == (size_t)pick) { idx = i; break; }
    const char *path = entries[idx].path;
    struct stat st;
    if (lstat(path, &st) != 0) { printf("Selected entry no longer exists or cannot be inspected.\nReason: %s\n", strerror(errno)); return; }
    if (S_ISLNK(st.st_mode)) { puts("Selected entry is now a symbolic link; refusing to change its target."); return; }
    char oldp[10], newp[10]; permission_string(st.st_mode, oldp);
    printf("Selected file:\n%s\nCurrent permission:\n%s\n", path, oldp);
    puts("1. 600 -> rw-------\n2. 644 -> rw-r--r--\n3. 660 -> rw-rw----\n4. 664 -> rw-rw-r--\n5. 700 -> rwx------\n6. 750 -> rwxr-x---\n7. 755 -> rwxr-xr-x");
    rc = read_line("Enter choice: ", input, sizeof(input)); if (rc <= 0) return;
    long c = strtol(input, &end, 10);
    static const mode_t modes[] = {0, 0600, 0644, 0660, 0664, 0700, 0750, 0755};
    if (errno || end == input || *end || c < 1 || c > 7) { puts("Invalid choice."); return; }
    mode_t desired = modes[c];
    if (chmod(path, desired) != 0) { printf("Permission change failed.\nReason: %s\n", strerror(errno)); return; }
    if (lstat(path, &st) != 0) { printf("Permission changed, but reread failed.\nReason: %s\n", strerror(errno)); return; }
    permission_string(st.st_mode, newp);
    if ((st.st_mode & 07777) != desired) { printf("Permission change did not produce requested mode.\nOld permission : %s\nObserved permission : %s\n", oldp, newp); return; }
    FILE *log = fopen("audit.log", "a");
    if (!log) { printf("Permission changed successfully, but audit.log could not be written: %s\n", strerror(errno)); }
    else {
        time_t now = time(NULL); struct tm tm; char timestamp[64] = "unknown";
        if (localtime_r(&now, &tm)) strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S %z", &tm);
        fprintf(log, "File: %s | Old: %s | New: %s | Time: %s\n", path, oldp, newp, timestamp);
        if (fclose(log) != 0) printf("Audit log write failed: %s\n", strerror(errno));
    }
    puts("\n============================================\n       PERMISSION CHANGED SUCCESSFULLY\n============================================");
    printf("Path           : %s\nOld permission : %s\nNew permission : %s\n============================================\n", path, oldp, newp);
}

static void view_audit_log(void) {
    FILE *f = fopen("audit.log", "r");
    if (!f) { if (errno == ENOENT) puts("No audit log found."); else printf("Cannot open audit.log: %s\n", strerror(errno)); return; }
    puts("\n============================================\n                AUDIT LOG\n============================================");
    char line[4096]; while (fgets(line, sizeof(line), f)) fputs(line, stdout);
    if (ferror(f)) printf("Error reading audit.log: %s\n", strerror(errno));
    fclose(f);
    puts("============================================");
}

int main(void) {
    puts("============================================\n          FILE PERMISSION AUDITOR\n============================================");
    if (!get_valid_directory()) { free_entries(); return 1; }
    for (;;) {
        puts("\n============================================\n                  MENU\n============================================\n1. Scan Directory\n2. Fix File Permission\n3. View Audit Log\n4. View Scan Report\n5. Filter Scan Results\n6. Exit\n============================================");
        char input[128]; int rc = read_line("Enter choice: ", input, sizeof(input));
        if (rc == 0) break;
        if (rc < 0) continue;
        char *end; errno = 0; long choice = strtol(input, &end, 10);
        if (errno || end == input || *end) { puts("Invalid input. Please enter a number."); continue; }
        switch (choice) {
            case 1: scan_selected_directory(); break;
            case 2: fix_permission(); break;
            case 3: view_audit_log(); break;
            case 4: show_report(); break;
            case 5: filter_results(); break;
            case 6: free_entries(); return 0;
            default: puts("Invalid choice.");
        }
    }
    free_entries(); return 0;
}
