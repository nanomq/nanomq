
int process_is_alive(int pid);
int process_send_signal(int pid, int signal);
int pidgrp_send_signal(int pid, int signal);
int process_daemonize(void);
int process_create_child(int(*child_run)(void *), void *data);
