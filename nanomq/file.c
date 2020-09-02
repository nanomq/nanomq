
/***
 *
 ***/

#include "include/nanomq.h"
#include "include/file.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <mtd/mtd-user.h>
#include <sys/ioctl.h>

#define NG_MODE	(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

static char fpath_tmp[100];

int file_trunc_to_zero(const char *fpath)
{
	int fd;

	debug_msg("fpath = %s\n", fpath);

	fd = open(fpath, O_WRONLY | O_CREAT | O_TRUNC, NG_MODE);
	if (fd >= 0)
		close(fd);

	return 0;
}

/*return 1 if exists*/
int file_exists(const char *fpath)
{
	struct stat st;
	int ret;

	ret = stat(fpath, &st) == 0 ? 1 : 0;
	debug_msg("%s: %i", fpath, ret);

	return ret;
}

int file_is_symlink(const char *fpath)
{
	int ret;
	struct stat st;

	ret = lstat(fpath, &st);
	if (ret != 0)
		return 0;

	return S_ISLNK(st.st_mode);
}

int file_size(const char *fpath)
{
	int ret;
	struct stat st;

	if (!file_exists(fpath))
		return 0;

	ret = stat(fpath, &st);
	if (ret != 0)
		return -1;

	return st.st_size;
}

int file_create_symlink(const char *file_path, const char *link_path)
{
	debug_msg("%s => %s", file_path, link_path);
	return symlink(file_path, link_path);
}

int file_read_int(const char *fpath_fmt, ...)
{
	va_list args;
	char buff[10];
	int fd, ret = 0;

	va_start(args, fpath_fmt);
	vsnprintf(fpath_tmp, sizeof(fpath_tmp), fpath_fmt, args);
	va_end(args);

	if (!file_exists(fpath_tmp))
		goto out;

	fd = open(fpath_tmp, O_RDONLY);
	if (fd < 0)
		goto out;

	ret = read(fd, buff, sizeof(buff));
	if (ret < 0)
		goto close;

	ret = strtol(buff, (char **)NULL, 10);
	debug_msg("fpath = %s, pid = %d", fpath_tmp, ret);

close:
	close(fd);
out:
	return ret;
}

int file_read_string(const char *fpath, char *buff, int buff_len)
{
	int fd, ret = 0;

	if (!file_exists(fpath))
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

int file_delete(const char *fpath)
{
	if (!fpath)
		return 0;

	debug_msg("%s", fpath);
	return unlink(fpath);
}

int file_create_dir(const char *fpath)
{
	char *last_slash = NULL, *fpath_edit = NULL;
	int ret = -1;

	debug_msg("dir = %s", fpath);

	if (fpath[strlen(fpath) - 1] != '/') {
		fpath_edit = malloc(strlen(fpath) + 1);
		if (!fpath_edit)
			return -1;

		strncpy(fpath_edit, fpath, strlen(fpath) + 1);
		fpath_edit[strlen(fpath)] = '\0';

		last_slash = strrchr(fpath_edit, '/');

		/* not a single slash in the string ? */
		if (!last_slash)
			goto out;

		*last_slash = '\0';
		fpath = fpath_edit;
	}

	debug_msg("mkdir = %s", fpath);
	ret = mkdir(fpath, 0777);
out:
	free(fpath_edit);

	return ret;
}

int file_write_int(int val, const char *fpath_fmt, ...)
{
	int fd;
	va_list args;
	char buff[10], buff_len;

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

int file_write_string(const char *fpath, const char *string)
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

int file_append_string(const char *fpath, const char *string_fmt, ...)
{
	va_list args;
	char string[100];
	int fd;

	if (!fpath)
		goto out;

	debug_msg("string_fmt = %s", string_fmt);

	va_start(args, string_fmt);
	vsnprintf(string, sizeof(string), string_fmt, args);
	string[sizeof(string)-1] = '\0';
	va_end(args);
	debug_msg("fpath = %s, string = %s", fpath, string);

	fd = open(fpath, O_CREAT | O_WRONLY | O_APPEND, NG_MODE);
	if (fd < 0) {
		debug_msg("Error - can't open file '%s' to append string: '%s'",
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

char *file_find_line(const char *fpath, const char *string)
{
	char *line_ptr = NULL, *ptr;
	FILE *fd;
	size_t len = 0;

	debug_msg("fpath = %s, string = %s", fpath, string);

	if (!fpath)
		goto out;

	if (!string)
		goto out;

	fd = fopen(fpath, "r");
	if (!fd)
		goto out;

	while (getline(&line_ptr, &len, fd) != -1) {
		ptr = strcasestr(line_ptr, string);

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

int file_read_symlink_target(const char *fpath, char *buff, int buff_len)
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

int file_delete_symlink_target(const char *fpath)
{
	int ret;
	char path_buff[100];

	ret = file_read_symlink_target(fpath, path_buff, sizeof(path_buff));
	if (ret < 0)
		return ret;

	debug_msg("file %s", path_buff);
	return file_delete(path_buff);
}

int file_is_directory(const char *fpath)
{
	int ret;
	struct stat st;

	ret = lstat(fpath, &st);
	if (ret != 0)
		return 0;

	debug_msg("fpath = %s, is_directory = %d", fpath, S_ISDIR(st.st_mode));
	return S_ISDIR(st.st_mode);
}

int file_read_bin(const char *fpath, unsigned char **buff,
		  unsigned int offset, unsigned int length)
{
	int fd, ret = 0;

	if (!file_exists(fpath))
		goto out;

	fd = open(fpath, O_RDONLY);
	if (fd < 0)
		goto out;

	*buff = malloc(length + 1);
	if (!*buff)
		goto close;

	lseek(fd, offset, SEEK_SET);

	ret = read(fd, *buff, length);
	if (ret < 0)
		goto close;

	/*if (ret > 1)
		*buff[ret - 1] = '\0';*/
	debug_msg("fpath = %s, offset = %u, length = %u", fpath, offset,
		  length);

close:
	close(fd);
out:
	return ret;
}

unsigned int file_mtd_size_get(const char *fpath)
{
	mtd_info_t mtd_info;
	unsigned int res = 0;
	int fd, ret;

	debug_msg("fpath = %s", fpath);

	if (!fpath)
		goto out;

	fd = open(fpath, O_RDONLY);
	if (fd < 0)
		goto out;

	ret = ioctl(fd, MEMGETINFO, &mtd_info);
	if (ret < 0)
		goto out_close;

	res = mtd_info.size;

out_close:
	close(fd);
out:
	return res;
}

int file_mtd_write(const char *fpath, unsigned char *buff, unsigned int buff_len)
{
	mtd_info_t mtd_info;
	erase_info_t ei;
	unsigned int res = 0;
	int fd, ret;

	debug_msg("fpath = %s", fpath);

	if (!fpath)
		goto out;

	fd = open(fpath, O_RDWR);
	if (fd < 0)
		goto out;

	ret = ioctl(fd, MEMGETINFO, &mtd_info);
	if (ret < 0)
		goto out_close;

	ei.length = mtd_info.erasesize;

	for (ei.start = 0; ei.start < mtd_info.size; ei.start += mtd_info.erasesize) {
		ioctl(fd, MEMUNLOCK, &ei);
		ioctl(fd, MEMERASE, &ei);
	}

	res = write(fd, buff, buff_len);

out_close:
	close(fd);
out:
	return res;
}

int file_truncr_to_sep(const char *fpath, char *separator)
{
	int fd, read_len;
	FILE *fd_tmp;
	char *line_ptr = NULL;
	size_t line_len = 0, trunc_len = 0, trunc_len_tmp = 0;

	debug_msg("fpath = %s, separator = %s", fpath, separator);

	fd_tmp = fopen(fpath, "r");
	if (!fd_tmp)
		goto write_sep;

	while ((read_len = getline(&line_ptr, &line_len, fd_tmp)) != -1) {

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
	dprintf(fd, "%s\n", separator);

	return fd;
}

int file_extract_int(const char *fpath)
{
	char buff[16], *ptr;
	int ret = 0;

	if (!file_exists(fpath))
		goto out;

	file_read_string(fpath, buff, sizeof(buff));

	ptr = strpbrk(buff, "0123456789");
	if (!ptr)
		ptr = buff;

	ret = strtol(ptr, (char **)NULL, 10);
	debug_msg("fpath = %s, int = %d", fpath, ret);

out:
	return ret;
}

int file_append_int(const char *fpath, int value)
{
	int fd;
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

	write(fd, buff, buff_len);
	close(fd);
	return 1;

out:
	return 0;
error:
	return -1;
}
