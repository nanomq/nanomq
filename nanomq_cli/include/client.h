#ifndef NANOMQ_CLIENT_H
#define NANOMQ_CLIENT_H

extern int            publish_start(int argc, char **argv);
extern int            subscribe_start(int argc, char **argv);
extern int            connect_start(int argc, char **argv);
extern struct topic **addtopic(struct topic **endp, const char *s);
extern void           freetopic(struct topic *endp);
extern void           console(const char *fmt, ...);

#endif // NANOMQ_CLIENT_H
