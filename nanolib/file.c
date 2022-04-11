#include "nanomq.h"
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef NANO_PLATFORM_WINDOWS
#include <mswsock.h>
#include <winsock2.h>
#include <ws2def.h>
#else
#include <sys/ioctl.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "file.h"

#define NG_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

#ifdef NANO_PLATFORM_WINDOWS
#define nano_mkdir(path, mode) mkdir(path)
#else
#define nano_mkdir(path, mode) mkdir(path, mode)
#endif

static char fpath_tmp[100];

#ifndef NANO_PLATFORM_WINDOWS

static char *
nano_strcasestr(const char *s1, const char *s2)
{
	return (strcasestr(s1, s2));
}

int
nano_fdprintf(int fd, char *fmt, ...)
{
	va_list ap;
	int     rc;
	va_start(ap, fmt);
	rc = dprintf(fd, fmt, ap);
	va_end(ap);
	return rc;
}

int64_t
nano_getline(char **restrict line, size_t *restrict len, FILE *restrict fp)
{
	return getline(line, len, fp);
}

#else

static char *
nano_strcasestr(const char *s1, const char *s2)
{
	const char *t1, *t2;
	while (*s1) {
		for (t1 = s1, t2 = s2; *t1 && *t2; t2++, t1++) {
			if (tolower(*t1) != tolower(*t2)) {
				break;
			}
		}
		if (*t2 == 0) {
			return ((char *) s1);
		}
		s1++;
	}
	return (NULL);
}

int
nano_fdprintf(int fd, char *fmt, ...)
{
	va_list ap;
	int     rc;
	va_start(ap, fmt);
	FILE *f = _fdopen(fd, "w");
	rc      = vfprintf(f, fmt, ap);
	fclose(f);
	va_end(ap);
	return rc;
}

int64_t
nano_getline(char **restrict line, size_t *restrict len, FILE *restrict fp)
{
	// Check if either line, len or fp are NULL pointers
	if (line == NULL || len == NULL || fp == NULL) {
		errno = EINVAL;
		return -1;
	}

	// Use a chunk array of 128 bytes as parameter for fgets
	char chunk[128];

	// Allocate a block of memory for *line if it is NULL or smaller than
	// the chunk array
	if (*line == NULL || *len < sizeof(chunk)) {
		*len = sizeof(chunk);
		if ((*line = malloc(*len)) == NULL) {
			errno = ENOMEM;
			return -1;
		}
	}

	// "Empty" the string
	(*line)[0] = '\0';

	while (fgets(chunk, sizeof(chunk), fp) != NULL) {
		// Resize the line buffer if necessary
		size_t len_used   = strlen(*line);
		size_t chunk_used = strlen(chunk);

		if (*len - len_used < chunk_used) {
			// Check for overflow
			if (*len > SIZE_MAX / 2) {
				errno = EOVERFLOW;
				return -1;
			} else {
				*len *= 2;
			}

			if ((*line = realloc(*line, *len)) == NULL) {
				errno = ENOMEM;
				return -1;
			}
		}

		// Copy the chunk to the end of the line buffer
		memcpy(*line + len_used, chunk, chunk_used);
		len_used += chunk_used;
		(*line)[len_used] = '\0';

		// Check if *line contains '\n', if yes, return the *line
		// length
		if ((*line)[len_used - 1] == '\n') {
			return len_used;
		}
	}

	return -1;
}

#endif

int
nano_file_trunc_to_zero(const char *fpath)
{
	int fd;

	debug_msg("fpath = %s\n", fpath);

	fd = open(fpath, O_WRONLY | O_CREAT | O_TRUNC, NG_MODE);
	if (fd >= 0)
		close(fd);

	return 0;
}

/*return 1 if exists*/
int
nano_file_exists(const char *fpath)
{
	struct stat st;
	int         ret;

	ret = stat(fpath, &st) == 0 ? 1 : 0;
	debug_msg("%s: %i", fpath, ret);

	return ret;
}

int
file_size(const char *fpath)
{
	int         ret;
	struct stat st;

	if (!nano_file_exists(fpath))
		return 0;

	ret = stat(fpath, &st);
	if (ret != 0)
		return -1;

	return st.st_size;
}

int
file_read_int(const char *fpath_fmt, ...)
{
	va_list args;
	char    buff[10];
	int     fd, ret = 0;

	va_start(args, fpath_fmt);
	vsnprintf(fpath_tmp, sizeof(fpath_tmp), fpath_fmt, args);
	va_end(args);

	if (!nano_file_exists(fpath_tmp))
		goto out;

	fd = open(fpath_tmp, O_RDONLY);
	if (fd < 0)
		goto out;

	ret = read(fd, buff, sizeof(buff));
	if (ret < 0)
		goto close;

	ret = strtol(buff, (char **) NULL, 10);
	debug_msg("fpath = %s, pid = %d", fpath_tmp, ret);

close:
	close(fd);
out:
	return ret;
}

int
file_read_string(const char *fpath, char *buff, int buff_len)
{
	int fd, ret = 0;

	if (!nano_file_exists(fpath))
		goto out;

	fd = open(fpath, O_RDONLY);
	if (fd < 0)
		goto out;

	ret = read(fd, buff, buff_len);
	if (ret < 0)
		goto close;

	if (ret > 0)
		buff[ret - 1] = '\0';

	debug_msg("fpath = %s, string = %s", fpath, buff);

close:
	close(fd);
out:
	return ret;
}

int
file_delete(const char *fpath)
{
	if (!fpath)
		return 0;

	debug_msg("%s", fpath);
	return unlink(fpath);
}

int
file_create_dir(const char *pName)
{

	struct stat sb;
	char       *slash;
	char       *path;
	int         done = 0;

	/* validate given args */
	if ((pName == NULL) || (*pName == 0)) {
		debug_msg("ERR: bad/illegal pName");
		return (-1);
	}

	/* dup pName for processing and set slash to start of path */
	path  = strdup(pName);
	slash = path;

	/* create dir after dir ... */
	while (!done) {
		slash += strspn(slash, "/");
		slash += strcspn(slash, "/");
		if (*slash == '\0') {
			done = 1;
		}
		*slash = '\0';

		if (stat(path, &sb)) {
			if (errno != ENOENT ||
			    (nano_mkdir(path, 0777) && errno != EEXIST)) {
				debug_msg(
				    "ERR: %s (%s)", strerror(errno), path);
				free(path);
				return (-1);
			}
		} else if (!S_ISDIR(sb.st_mode)) {
			debug_msg("ERR: %s (%s)", strerror(ENOTDIR), path);
			free(path);
			return (-1);
		}
		if (done == 0)
			*slash = '/';
	}

	debug_msg("DBG: %s successfully created", pName);
	free(path);
	return (0);
}

int
file_write_int(int val, const char *fpath_fmt, ...)
{
	int     fd;
	va_list args;
	char    buff[13], buff_len;

	if (!fpath_fmt)
		goto out;

	va_start(args, fpath_fmt);
	vsnprintf(fpath_tmp, sizeof(fpath_tmp), fpath_fmt, args);
	va_end(args);

	debug_msg("fpath = %s, int = %i", fpath_tmp, val);

	buff_len = sprintf(buff, "%i\n", val);

	fd = open(fpath_tmp, O_CREAT | O_WRONLY | O_TRUNC, NG_MODE);
	if (fd < 0) {
		debug_msg("Error - can't open file '%s' to write pid: %s",
		    fpath_tmp, strerror(errno));
		goto error;
	}

	write(fd, buff, buff_len);
	close(fd);
	return 1;

out:
	return 0;
error:
	return -1;
}

int
file_write_string(const char *fpath, const char *string)
{
	int fd;

	if (!fpath)
		goto out;

	debug_msg("fpath = %s, string = '%s'", fpath, string);

	fd = open(fpath, O_CREAT | O_WRONLY | O_TRUNC, NG_MODE);
	if (fd < 0) {
		debug_msg("Error - can't open file '%s' to write string: %s",
		    fpath, strerror(errno));
		goto error;
	}

	write(fd, string, strlen(string));
	close(fd);
	return 1;

out:
	return 0;
error:
	return -1;
}

int
file_append_string(const char *fpath, const char *string_fmt, ...)
{
	va_list args;
	char    string[100];
	int     fd;

	if (!fpath)
		goto out;

	debug_msg("string_fmt = %s", string_fmt);

	va_start(args, string_fmt);
	vsnprintf(string, sizeof(string), string_fmt, args);
	string[sizeof(string) - 1] = '\0';
	va_end(args);
	debug_msg("fpath = %s, string = %s", fpath, string);

	fd = open(fpath, O_CREAT | O_WRONLY | O_APPEND, NG_MODE);
	if (fd < 0) {
		debug_msg(
		    "Error - can't open file '%s' to append string: '%s'",
		    fpath, strerror(errno));
		goto error;
	}

	write(fd, string, strlen(string));
	close(fd);
	return 1;

out:
	return 0;
error:
	return -1;
}

char *
file_find_line(const char *fpath, const char *string)
{
	char  *line_ptr = NULL, *ptr;
	FILE  *fd;
	size_t len = 0;

	debug_msg("fpath = %s, string = %s", fpath, string);

	if (!fpath)
		goto out;

	if (!string)
		goto out;

	fd = fopen(fpath, "r");
	if (!fd)
		goto out;

	while (nano_getline(&line_ptr, &len, fd) != -1) {
		ptr = nano_strcasestr(line_ptr, string);

		if (!ptr)
			continue;

		goto found;
	}

	free(line_ptr);
	fclose(fd);
out:
	return NULL;

found:
	fclose(fd);
	return line_ptr;
}

#ifdef NANO_PLATFORM_WINDOWS

int
file_is_symlink(const char *fpath)
{
	return -1;
}
int
file_create_symlink(const char *file_path, const char *link_path)
{
	return -1;
}
int
file_read_symlink_target(const char *fpath, char *buff, int buff_len)
{
	return -1;
}
int
file_delete_symlink_target(const char *fpath)
{
	return -1;
}

#else

int
file_is_symlink(const char *fpath)
{
	int ret;
	struct stat st;
	ret = lstat(fpath, &st);
	if (ret != 0)
		return 0;

	return S_ISLNK(st.st_mode);
}

int
file_create_symlink(const char *file_path, const char *link_path)
{
	debug_msg("%s => %s", file_path, link_path);
	return symlink(file_path, link_path);
}

int
file_read_symlink_target(const char *fpath, char *buff, int buff_len)
{
	int ret;

	if (!file_is_symlink(fpath))
		return -1;

	memset(buff, 0, buff_len);
	ret = readlink(fpath, buff, buff_len);
	if (ret < 0)
		return ret;

	debug_msg("file %s links to %s", fpath, buff);
	return 0;
}

int
file_delete_symlink_target(const char *fpath)
{
	int ret;
	char path_buff[100];

	ret = file_read_symlink_target(fpath, path_buff, sizeof(path_buff));
	if (ret < 0)
		return ret;

	debug_msg("file %s", path_buff);
	return file_delete(path_buff);
}
#endif

int
file_is_directory(const char *fpath)
{
	int ret;
	struct stat st;

#if NANO_PLATFORM_WINDOWS
	ret = stat(fpath, &st);
#else
	ret = lstat(fpath, &st);
#endif
	if (ret != 0)
		return 0;

	debug_msg("fpath = %s, is_directory = %d", fpath, S_ISDIR(st.st_mode));
	return S_ISDIR(st.st_mode);
}

int
file_read_bin(const char *fpath, unsigned char **buff, unsigned int offset,
    unsigned int length)
{
	int fd, ret = 0;

	if (!nano_file_exists(fpath))
		goto out;

	fd = open(fpath, O_RDONLY);
	if (fd < 0)
		goto out;

	*buff = calloc(1, length + 1);
	if (!*buff)
		goto close;

	lseek(fd, offset, SEEK_SET);

	ret = read(fd, *buff, length);
	if (ret < 0)
		goto close;

	/*if (ret > 1)
	 *buff[ret - 1] = '\0';*/
	debug_msg(
	    "fpath = %s, offset = %u, length = %u", fpath, offset, length);

close:
	close(fd);
out:
	return ret;
}

int
file_truncr_to_sep(const char *fpath, char *separator)
{
	int fd, read_len;
	FILE *fd_tmp;
	char *line_ptr = NULL;
	size_t line_len = 0, trunc_len = 0, trunc_len_tmp = 0;

	debug_msg("fpath = %s, separator = %s", fpath, separator);

	fd_tmp = fopen(fpath, "r");
	if (!fd_tmp)
		goto write_sep;

	while ((read_len = nano_getline(&line_ptr, &line_len, fd_tmp)) != -1) {

		if (strncmp(line_ptr, separator, strlen(separator)) == 0) {
			trunc_len += trunc_len_tmp;
			trunc_len_tmp = 0;
		}

		trunc_len_tmp += read_len;
	}

	fclose(fd_tmp);
	free(line_ptr);

write_sep:
	fd = open(fpath, O_RDWR | O_CREAT, NG_MODE);
	if (fd < 0)
		return -1;

	ftruncate(fd, trunc_len);
	lseek(fd, trunc_len, SEEK_SET);
	nano_fdprintf(fd, "%s\n", separator);

	return fd;
}

int
file_extract_int(const char *fpath)
{
	char buff[16], *ptr;
	int ret = 0;

	if (!nano_file_exists(fpath))
		goto out;

	file_read_string(fpath, buff, sizeof(buff));

	ptr = strpbrk(buff, "0123456789");
	if (!ptr)
		ptr = buff;

	ret = strtol(ptr, (char **) NULL, 10);
	debug_msg("fpath = %s, int = %d", fpath, ret);

out:
	return ret;
}

int
file_append_int(const char *fpath, int value)
{
	int fd, ret;
	char buff[10], buff_len;

	if (!fpath)
		goto out;

	buff_len = sprintf(buff, "%i\n", value);

	fd = open(fpath, O_CREAT | O_WRONLY | O_APPEND, NG_MODE);
	if (fd < 0) {
		debug_msg("Error - can't open file '%s' to append string: %s",
		    fpath, strerror(errno));
		goto error;
	}

	ret = write(fd, buff, buff_len);
	close(fd);
	return 1;

out:
	return 0;
error:
	return -1;
}

int
file_load_data(const char *filepath, void **data)
{
	int64_t size;
	if ((size = file_size(filepath)) <= 0) {
		return -1;
	}

	return file_read_bin(filepath, (uint8_t **) data, 0, size);
}