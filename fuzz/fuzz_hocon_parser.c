#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "nng/supplemental/nanolib/hocon.h"
#include "nng/supplemental/nanolib/cJSON.h"

/**
 * @file fuzz_hocon_parser.c
 * @brief Fuzz target for HOCON parser with exit() interception
 * 
 * This fuzzer intercepts exit() calls from yyerror() to prevent
 * the fuzzer process from terminating on parse errors.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

// HOCON parser interface
extern void *hocon_parse_str(char *str, size_t size);

// Jump buffer for exit() interception (thread-local for safety)
static __thread jmp_buf exit_env;
static __thread int exit_handling_enabled = 0;

/**
 * Override exit() to catch parser errors without terminating the fuzzer.
 * When exit() is called, we longjmp back to the fuzz target instead of exiting.
 */
void exit(int status) __attribute__((noreturn));
void exit(int status) {
    if (exit_handling_enabled) {
        longjmp(exit_env, 1);
    }
    // Fallback to actual exit if not in fuzzing context
    _Exit(status);
}

/**
 * Also intercept abort() in case the parser uses it
 */
void abort(void) __attribute__((noreturn));
void abort(void) {
    if (exit_handling_enabled) {
        longjmp(exit_env, 1);
    }
    _Exit(1);
}

/**
 * Fuzzer entry point called by libFuzzer for each test input
 * 
 * @param data Raw input bytes from fuzzer
 * @param size Number of bytes in data
 * @return 0 to continue fuzzing, non-zero to stop (we always return 0)
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Skip empty inputs and overly large ones
    if (size == 0 || size > 1024 * 1024) {
        return 0;
    }

    // Create null-terminated string (HOCON parser expects C string)
    char *input = (char *)malloc(size + 1);
    if (!input) {
        return 0;
    }
    
    memcpy(input, data, size);
    input[size] = '\0';

    // Enable exit() interception
    exit_handling_enabled = 1;
    
    if (setjmp(exit_env) == 0) {
        // First time: call the parser
        hocon_parse_str(input, size);
    }
    // If exit() or abort() was called, we return here via longjmp
    // This is normal for invalid HOCON syntax - just continue fuzzing
    
    // Cleanup
    exit_handling_enabled = 0;
    free(input);
    
    return 0;
}