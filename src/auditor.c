#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#define MAX_FILES 1000

int total_files = 0;
int safe_files = 0;
int warning_files = 0;
int critical_files = 0;

char scan_path[1024] = "";

char scanned_files[MAX_FILES][2048];
int scanned_file_count = 0;


/* Convert permission bits to rwxrwxrwx format */
void permission_string(mode_t mode, char *p)
{
    p[0] = (mode & S_IRUSR) ? 'r' : '-';
    p[1] = (mode & S_IWUSR) ? 'w' : '-';
    p[2] = (mode & S_IXUSR) ? 'x' : '-';

    p[3] = (mode & S_IRGRP) ? 'r' : '-';
    p[4] = (mode & S_IWGRP) ? 'w' : '-';
    p[5] = (mode & S_IXGRP) ? 'x' : '-';

    p[6] = (mode & S_IROTH) ? 'r' : '-';
    p[7] = (mode & S_IWOTH) ? 'w' : '-';
    p[8] = (mode & S_IXOTH) ? 'x' : '-';

    p[9] = '\0';
}


/* Decide risk level */
const char *risk_level(mode_t mode)
{
    if (mode & S_IWOTH)
        return "CRITICAL";

    if (mode & S_IWGRP)
        return "WARNING";

    return "SAFE";
}


/* Check one file */
void check_file(const char *path)
{
    struct stat st;
    char permission[10];
    const char *risk;

    if (lstat(path, &st) != 0)
        return;

    permission_string(st.st_mode, permission);
    risk = risk_level(st.st_mode);

    total_files++;

    /* Save file path for the Fix Permission option */
    if (scanned_file_count < MAX_FILES)
    {
        strcpy(scanned_files[scanned_file_count], path);
        scanned_file_count++;
    }

    printf("\nFile       : %s\n", path);
    printf("Permission : %s\n", permission);
    printf("Risk       : %s\n", risk);

    if (strcmp(risk, "CRITICAL") == 0)
        critical_files++;
    else if (strcmp(risk, "WARNING") == 0)
        warning_files++;
    else
        safe_files++;
}


/* Recursively scan directory */
void scan_directory(const char *path)
{
    DIR *directory;
    struct dirent *entry;
    struct stat st;
    char full_path[2048];

    directory = opendir(path);

    if (directory == NULL)
    {
        printf("Cannot open directory: %s\n", path);
        printf("Reason: %s\n", strerror(errno));
        return;
    }

    while ((entry = readdir(directory)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }

        snprintf(full_path,
                 sizeof(full_path),
                 "%s/%s",
                 path,
                 entry->d_name);

        if (lstat(full_path, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode))
        {
            scan_directory(full_path);
        }
        else
        {
            check_file(full_path);
        }
    }

    closedir(directory);
}


/* Scan selected directory */
void scan_selected_directory()
{
    total_files = 0;
    safe_files = 0;
    warning_files = 0;
    critical_files = 0;
    scanned_file_count = 0;

    printf("\n============================================\n");
    printf("              DIRECTORY SCAN\n");
    printf("============================================\n");

    printf("Scanning: %s\n", scan_path);
    printf("--------------------------------------------\n");

    scan_directory(scan_path);

    printf("\nScan completed.\n");
    printf("Total files found: %d\n", scanned_file_count);
}


/* Display scan report */
void show_report()
{
    printf("\n============================================\n");
    printf("                SCAN REPORT\n");
    printf("============================================\n");

    printf("Directory   : %s\n", scan_path);
    printf("Total Files : %d\n", total_files);
    printf("Safe        : %d\n", safe_files);
    printf("Warning     : %d\n", warning_files);
    printf("Critical    : %d\n", critical_files);

    printf("============================================\n");
}


/* Fix file permission */
void fix_permission()
{
    int file_choice;
    int choice;
    mode_t new_mode;

    struct stat st;

    char old_permission[10];
    char new_permission[10];

    if (scanned_file_count == 0)
    {
        printf("\n============================================\n");
        printf("              NO FILES AVAILABLE\n");
        printf("============================================\n");
        printf("Please scan a directory first.\n");
        printf("============================================\n");
        return;
    }

    printf("\n============================================\n");
    printf("            FIX FILE PERMISSION\n");
    printf("============================================\n");

    printf("\nFiles found during scan:\n\n");

    for (int i = 0; i < scanned_file_count; i++)
    {
        printf("%d. %s\n", i + 1, scanned_files[i]);
    }

    printf("\nEnter file number: ");

    if (scanf("%d", &file_choice) != 1)
    {
        printf("\nInvalid input.\n");

        while (getchar() != '\n');

        return;
    }

    if (file_choice < 1 || file_choice > scanned_file_count)
    {
        printf("\nInvalid file number.\n");
        return;
    }

    char *path = scanned_files[file_choice - 1];

    if (lstat(path, &st) != 0)
    {
        printf("\nFile cannot be accessed.\n");
        return;
    }

    permission_string(st.st_mode, old_permission);

    printf("\nSelected file:\n%s\n", path);
    printf("Current permission: %s\n", old_permission);

    printf("\nChoose new permission:\n");

    printf("1. 600  -> rw-------\n");
    printf("2. 644  -> rw-r--r--\n");
    printf("3. 660  -> rw-rw----\n");
    printf("4. 664  -> rw-rw-r--\n");
    printf("5. 700  -> rwx------\n");
    printf("6. 750  -> rwxr-x---\n");
    printf("7. 755  -> rwxr-xr-x\n");

    printf("\nEnter choice: ");

    if (scanf("%d", &choice) != 1)
    {
        printf("\nInvalid input.\n");

        while (getchar() != '\n');

        return;
    }

    switch (choice)
    {
        case 1:
            new_mode = 0600;
            break;

        case 2:
            new_mode = 0644;
            break;

        case 3:
            new_mode = 0660;
            break;

        case 4:
            new_mode = 0664;
            break;

        case 5:
            new_mode = 0700;
            break;

        case 6:
            new_mode = 0750;
            break;

        case 7:
            new_mode = 0755;
            break;

        default:
            printf("\nInvalid choice.\n");
            return;
    }

    if (chmod(path, new_mode) != 0)
    {
        printf("\nPermission change failed.\n");
        printf("Reason: %s\n", strerror(errno));
        return;
    }

    if (lstat(path, &st) != 0)
    {
        printf("\nPermission changed, but new permission could not be read.\n");
        return;
    }

    permission_string(st.st_mode, new_permission);

    /* Write change to audit log */
    FILE *log = fopen("audit.log", "a");

    if (log != NULL)
    {
        time_t now = time(NULL);

        fprintf(log,
                "File: %s | Old: %s | New: %s | Time: %s",
                path,
                old_permission,
                new_permission,
                ctime(&now));

        fclose(log);
    }

    printf("\n============================================\n");
    printf("       PERMISSION CHANGED SUCCESSFULLY\n");
    printf("============================================\n");

    printf("File           : %s\n", path);
    printf("Old permission : %s\n", old_permission);
    printf("New permission : %s\n", new_permission);

    printf("\nChange recorded in audit.log\n");
}


/* Display audit log */
void view_audit_log()
{
    FILE *log;
    char line[2048];

    printf("\n============================================\n");
    printf("                AUDIT LOG\n");
    printf("============================================\n");

    log = fopen("audit.log", "r");

    if (log == NULL)
    {
        printf("No audit log found.\n");
        printf("Make a permission change first.\n");
        printf("============================================\n");
        return;
    }

    while (fgets(line, sizeof(line), log) != NULL)
    {
        printf("%s", line);
    }

    fclose(log);

    printf("============================================\n");
}


/* Prepare the directory path */
void prepare_path(char *input)
{
    char temp[1024];

    if (strcmp(input, "root") == 0)
    {
        strcpy(scan_path, "/root");
    }
    else if (strcmp(input, ".") == 0)
    {
        if (getcwd(scan_path, sizeof(scan_path)) == NULL)
        {
            strcpy(scan_path, ".");
        }
    }
    else if (input[0] == '/')
    {
        strcpy(scan_path, input);
    }
    else
    {
        snprintf(temp, sizeof(temp), "/home/%s", input);
        strcpy(scan_path, temp);
    }
}


/* Ask for a valid and accessible directory */
void get_valid_directory()
{
    char input[1024];
    struct stat st;
    DIR *directory;

    while (1)
    {
        printf("\nEnter directory to scan: ");

        if (scanf("%1023s", input) != 1)
        {
            printf("\nInvalid input.\n");

            while (getchar() != '\n');

            continue;
        }

        prepare_path(input);

        /* Check whether the path exists */
        if (lstat(scan_path, &st) != 0)
        {
            printf("\n============================================\n");
            printf("                  ERROR\n");
            printf("============================================\n");
            printf("Directory not found.\n");
            printf("You entered: %s\n", input);
            printf("Tried path : %s\n", scan_path);
            printf("\nPlease enter the directory again.\n");
            printf("============================================\n");

            continue;
        }

        /* Check whether the path is actually a directory */
        if (!S_ISDIR(st.st_mode))
        {
            printf("\n============================================\n");
            printf("                  ERROR\n");
            printf("============================================\n");
            printf("The path is not a directory.\n");
            printf("You entered: %s\n", input);
            printf("\nPlease enter a directory again.\n");
            printf("============================================\n");

            continue;
        }

        /*
         * Important:
         * A directory may exist but still be inaccessible.
         * Try opening it before accepting the path.
         */
        directory = opendir(scan_path);

        if (directory == NULL)
        {
            printf("\n============================================\n");
            printf("                  ERROR\n");
            printf("============================================\n");
            printf("Directory exists but cannot be accessed.\n");
            printf("Reason: %s\n", strerror(errno));
            printf("Path    : %s\n", scan_path);
            printf("\nPlease enter a directory you have permission to access.\n");
            printf("For Codespaces, you can enter: .\n");
            printf("============================================\n");

            continue;
        }

        closedir(directory);

        printf("\nDirectory found and accessible.\n");
        printf("Using directory: %s\n", scan_path);

        break;
    }
}


/* Main program */
int main()
{
    int choice = 0;

    printf("\n============================================\n");
    printf("          FILE PERMISSION AUDITOR\n");
    printf("============================================\n");

    get_valid_directory();

    do
    {
        printf("\n\n============================================\n");
        printf("                  MENU\n");
        printf("============================================\n");

        printf("1. Scan Directory\n");
        printf("2. Fix File Permission\n");
        printf("3. View Audit Log\n");
        printf("4. View Scan Report\n");
        printf("5. Exit\n");

        printf("============================================\n");

        printf("Enter choice: ");

        if (scanf("%d", &choice) != 1)
        {
            printf("\nInvalid input. Please enter a number.\n");

            while (getchar() != '\n');

            continue;
        }

        switch (choice)
        {
            case 1:
                scan_selected_directory();
                break;

            case 2:
                fix_permission();
                break;

            case 3:
                view_audit_log();
                break;

            case 4:
                show_report();
                break;

            case 5:
                printf("\nExiting File Permission Auditor...\n");
                break;

            default:
                printf("\nInvalid choice. Please try again.\n");
        }

    } while (choice != 5);

    return 0;
}
