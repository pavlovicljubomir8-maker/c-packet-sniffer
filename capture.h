//owns shutdown signalling: the flag the loop checks and the SIGINT handler that clears it// capture.h owns shutdown signalling: the flag the loop checks and the SIGINT handler that clears it
#ifndef CAPTURE_H
#define CAPTURE_H
#include <signal.h>
//it's modified from a signal handler, so the compiler must not cache it and the write must be atomic.
extern volatile sig_atomic_t running;
void handle_sigint(int sig);
#endif
