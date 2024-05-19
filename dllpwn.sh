#!/bin/bash

set -euo pipefail

# Colors for better visualization
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Usage information
show_help() {
    cat <<EOF
Usage: dllpwn <process_to_inject> <init_data> [output_file]
       dllpwn --help | -h

Arguments:
  process_to_inject   Path to the process executable to inject the shared object into.
  init_data           Data to initialize the shared object with.
  output_file         (Optional) File to write the output to. Default is /tmp/test.txt.
EOF
    exit 0
}

# Check if help is requested
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    show_help
fi

# Check if sufficient arguments are provided
if [ "$#" -lt 2 ]; then
    echo -e "${RED}Error: Insufficient arguments.${NC}"
    show_help
fi

# Assign command-line arguments to variables
TARGET_PROCESS="${1:-}"
INIT_DATA="${2:-}"
OUTPUT_FILE="${3:-/tmp/test.txt}"

if [ -z "$TARGET_PROCESS" ]; then
    echo -e "${RED}Error: Missing target process.${NC}"
    show_help
fi

# Shared object C code
read -r -d '' SOURCE_CODE << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

#define MAX_PATH 4096

// Global variable to store initialization data
char initData[MAX_PATH] = {0};

// Shared object constructor
__attribute__((constructor))
void init(void) {
    const char *init_data = getenv("INIT_DATA");
    if (init_data) {
        strncpy(initData, init_data, MAX_PATH - 1);
        printf("Initialization data: %s\n", initData);
    } else {
        printf("No initialization data provided.\n");
    }
}

// Function prototype for the thread
void *myThread(void *lpvThreadParam);

// Thread function
void *myThread(void *lpvThreadParam) {
    // Wait for the process to finish if needed
    pid_t my_pid = getpid();
    while (kill(my_pid, 0) == 0) {
        sleep(1);
    }

    // Write initialization data to output file
    int fd = open("/tmp/test.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd != -1) {
        write(fd, initData, strlen(initData));
        close(fd);
        printf("Initialization data written to /tmp/test.txt\n");
    } else {
        printf("Failed to open /tmp/test.txt for writing.\n");
    }

    return NULL;
}
EOF

# Create a temporary directory for building the shared object
TEMP_DIR=$(mktemp -d)
SO_FILE="$TEMP_DIR/dllinject.so"
C_FILE="$TEMP_DIR/inject.c"

# Write the C code to a temporary file
echo "$SOURCE_CODE" > "$C_FILE"

# Compile the shared object
echo -e "${YELLOW}[*] Compiling the shared object...${NC}"
gcc -fPIC -shared -o "$SO_FILE" "$C_FILE" -pthread >/dev/null 2>&1

# Check if the compilation was successful
if [ $? -ne 0 ]; then
  echo -e "${RED}[!] Compilation of the shared object failed.${NC}"
  rm -rf "$TEMP_DIR"
  exit 1
fi

# Define the preload library path and the initialization data
export LD_PRELOAD="$SO_FILE"
export INIT_DATA="$INIT_DATA"
export OUTPUT_FILE="$OUTPUT_FILE"

# Launch the target process with the preloaded shared object
echo -e "${YELLOW}[*] Launching the target process with the preloaded shared object...${NC}"
"$TARGET_PROCESS" &>/dev/null &

# Capture the PID of the target process
TARGET_PID=$!

# Wait for the process to finish if needed
wait $TARGET_PID

# Cleanup
echo -e "${YELLOW}[*] Cleaning up...${NC}"
rm -rf "$TEMP_DIR"
unset LD_PRELOAD
unset INIT_DATA
unset OUTPUT_FILE

echo -e "${GREEN}[+] Process $TARGET_PROCESS executed with $SO_FILE preloaded.${NC}"
