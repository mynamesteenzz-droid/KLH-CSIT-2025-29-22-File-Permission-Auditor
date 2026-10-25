# KLH-CSIT-2026-22-File-Permission-Auditor
# File Permission Auditor

## Team Members

| Name | ID Number |
| P Neeharika | 2520090233 |
| G Shivani | 2520090046 |

**Supervisor:** M Raghupathi

## Abstract

File Permission Auditor is a security-focused application designed to analyze and identify unsafe access permissions assigned to files and directories.
The application scans a user-selected directory and examines the permissions associated with the owner, group, and other users.
It evaluates the read, write, and execute permissions of each file and identifies potentially risky configurations, such as files that are writable or executable by unauthorized users.
The detected permission issues are presented in a clear and understandable format, allowing users to easily identify files that may require attention.
The application can also provide an option to correct unsafe permissions by applying appropriate access settings to selected files.
This helps reduce the possibility of accidental modification or unauthorized access to important data.
The project demonstrates important operating system concepts including file systems, file permissions, ownership, access control, and system calls.
It provides a practical understanding of how operating systems control access to stored files and protect data from unauthorized modification or access.

## Setup and Execution Instructions

### Prerequisites

- Linux/Ubuntu environment
- GCC compiler
- Basic terminal access

### Setup

Clone the project repository:

```bash
git clone https://github.com/mynamesteenzz-droid/KLH-CSIT-2025-29-22-File-Permission-Auditor.git
cd File-Permission-Auditor
