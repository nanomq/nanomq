#ifndef NANOMQ_BENCH_H
#define NANOMQ_BENCH_H

#if !defined(NANO_PLATFORM_WINDOWS) && defined(SUPP_BENCH)
//TODO support windows later
extern int bench_start(int argc, char **argv);
extern int bench_dflt(int argc, char **argv);
#endif

#endif //NANOMQ_BENCH_H