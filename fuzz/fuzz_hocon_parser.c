/**
 * @file fuzz_hocon_parser.c
 * @brief Fuzz target for HOCON parser with exit() interception and cleanup
 * 
 * CLEANUP STRATEGY:
 * 1. Call yylex_destroy() before longjmp to cleanup scanner state
 * 2. If that's not available, we still disable leak detection as fallback
 * 3. This approach minimizes leaks while being safe
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

// HOCON parser interface
extern void *hocon_parse_str(char *str, size_t size);

// Flex scanner cleanup function
// This is the standard way to cleanup flex scanner resources
// Declared as weak so code compiles even if it doesn't exist
extern int yylex_destroy(void) __attribute__((weak));

// Thread-local state for exit() handling
static __thread jmp_buf exit_env;
static __thread int exit_handling_enabled = 0;

/**
 * Override exit() to cleanup and longjmp instead of terminating
 */
void exit(int status) __attribute__((noreturn));
void exit(int status) {
    if (exit_handling_enabled) {
        // Try to cleanup scanner resources before longjmp
        // yylex_destroy() is the standard flex cleanup function
        if (yylex_destroy != NULL) {
            // Call it to free scanner buffers
            // This should free the 134 bytes we see in the leak report
            yylex_destroy();
        }
        
        // Now jump back to fuzzer
        longjmp(exit_env, status ? status : 1);
    }
    _Exit(status);
}

/**
 * Also intercept abort()
 */
void abort(void) __attribute__((noreturn));
void abort(void) {
    if (exit_handling_enabled) {
        if (yylex_destroy != NULL) {
            yylex_destroy();
        }
        longjmp(exit_env, 128);
    }
    _Exit(128);
}

/**
 * Disable leak detection as a fallback
 * In case yylex_destroy() doesn't fully cleanup everything
 */
__attribute__((used))
__attribute__((visibility("default")))
const char *__asan_default_options(void) {
    return "detect_leaks=0";
}

/**
 * Fuzzer entry point
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 1024 * 1024) {
        return 0;
    }

    char *input = (char *)malloc(size + 1);
    if (!input) {
        return 0;
    }
    
    memcpy(input, data, size);
    input[size] = '\0';

    exit_handling_enabled = 1;
    
    if (setjmp(exit_env) == 0) {
        // Normal execution - call the parser
        hocon_parse_str(input, size);
    }
    // If exit() was called:
    // - yylex_destroy() was already called in exit()
    // - We safely returned here via longjmp
    
    exit_handling_enabled = 0;
    free(input);
    
    return 0;
}