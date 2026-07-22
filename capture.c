// capture.c
#include "capture.h"
volatile sig_atomic_t running = 1;
void handle_sigint(int sig) { (void)sig; running = 0; }
