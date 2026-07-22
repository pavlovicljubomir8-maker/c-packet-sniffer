// capture.h
#ifndef CAPTURE_H
#define CAPTURE_H
#include <signal.h>
extern volatile sig_atomic_t running;
void handle_sigint(int sig);
#endif
