#ifndef NANOMQ_CLIENT_H
#define NANOMQ_CLIENT_H

extern int pub_dflt(int argc, char **argv);
extern int sub_dflt(int argc, char **argv);
extern int conn_dflt(int argc, char **argv);
extern int pub_start(int argc, char **argv);
extern int sub_start(int argc, char **argv);
extern int conn_start(int argc, char **argv);
extern int client_stop(int argc, char **argv);
extern struct topic **
addtopic(struct topic **endp, const char *s);
extern void freetopic(struct topic *endp);

#endif // NANOMQ_CLIENT_H
