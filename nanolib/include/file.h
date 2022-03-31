#ifndef NANO_FILE_H
#define NANO_FILE_H

#include <stdio.h>
#include <stdint.h>

int   nano_file_trunc_to_zero(const char *fpath);
int   nano_file_exists(const char *fpath);
int64_t nano_getline(
    char **restrict line, size_t *restrict len, FILE *restrict fp);
int   file_is_symlink(const char *fpath);
int   file_size(const char *fpath);
int   file_create_symlink(const char *file_path, const char *link_path);
int   file_read_int(const char *fpath_fmt, ...);
int   file_read_string(const char *fpath, char *buff, int buff_len);
int   file_delete(const char *fpath);
int   file_read_symlink_target(const char *fpath, char *buff, int buff_len);
int   file_delete_symlink_target(const char *fpath);
int   file_create_dir(const char *fpath);
int   file_write_int(int val, const char *fpath_fmt, ...);
int   file_write_string(const char *fpath, const char *string);
int   file_append_string(const char *fpath, const char *string_fmt, ...);
char *file_find_line(const char *fpath, const char *string);
int   file_is_directory(const char *fpath);
int file_read_bin(const char *fpath, unsigned char **buff, unsigned int offset,
    unsigned int length);
int file_truncr_to_sep(const char *fpath, char *separator);
int file_append_int(const char *fpath, int value);
int file_extract_int(const char *fpath);
int file_load_data(const char *filepath, void **data);
#endif
