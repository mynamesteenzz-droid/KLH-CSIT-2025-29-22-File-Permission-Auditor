The launcher compiles the project, then opens a new terminal window for the auditor. Running `./auditor` directly keeps>

At startup, enter an absolute path such as `/root/subbarao` or a relative path such as `subbarao`, `.`, or `../somefold>

A simple name with no `/` also supports search by name. The program first checks the current working directory, then re>

For example, from the project directory, entering `subbarao` can locate `/root/subbarao`. In WSL, a name such as `Colle>

## Scanning, permissions, and risk

Each scan resets prior results and reads the current filesystem with `opendir()`, `readdir()`, and `lstat()`. It recurs>

Risk is calculated from current permission bits:

- **SAFE**: no group-write or other-write bit.
- **WARNING**: group-write bit set.
- **CRITICAL**: other/world-write bit set.

The report totals scanned filesystem entries, including files and directories. **Filter Scan Results** shows all result>

## Fix permissions and audit log
After scanning, choose a listed non-symbolic-link entry. The program reads its current mode, applies one of `600`, `644>

