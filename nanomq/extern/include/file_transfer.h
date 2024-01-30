#ifndef NANO_EXTERN_FILETRANS
#define NANO_EXTERN_FILETRANS

#define MD5_LEN 32

int CalcFileMD5(char *file_name, char *md5_sum);
int CalcMD5n(char *binary, size_t len, char *tmpfpath, char **md5res);


#endif
