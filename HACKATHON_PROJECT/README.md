# Copy-on-Write Memory Demonstrator

## Problem Statement
Demonstrate how memory is shared after `fork()` and copied when a process modifies it.

## Objective
To demonstrate Copy-on-Write (COW) behavior and parent-child process memory isolation using C on Linux.

## Technologies Used
- C programming language
- Linux operating system
- GCC compiler
- `mmap()`, `fork()`, `waitpid()` and `getrusage()`

## How It Works
1. Allocate 16 MiB of private anonymous memory.
2. Initialize every page with the value `42`.
3. Create a child process using `fork()`.
4. The child changes one byte on every page to `99`.
5. The parent waits for the child and verifies its original value.

## Test Results
- Memory allocated: 16 MiB
- Page size: 4096 bytes on the test system
- Pages initialized: 4096
- Child value after modification: `99`
- Parent value after child exits: `42`
- Parent data preserved: **YES**

The child’s minor page-fault count provides supporting evidence of page-fault activity. It is not a direct measurement of the number of physical pages copied.

## Novelty
This project turns an operating-system memory-management concept into a practical, repeatable experiment with observable output.

## Limitations
The program demonstrates process isolation and behavior consistent with COW. It does not directly inspect physical memory mappings.

## Future Enhancements
- Compare different memory sizes.
- Run repeated benchmarks.
- Visualize memory changes and page-fault results.
