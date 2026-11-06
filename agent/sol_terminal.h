#ifndef BC_SOL_TERMINAL_H
#define BC_SOL_TERMINAL_H
#include <stdint.h>
int bc_sol_terminal_open(void);
/* Nonblocking input: 1 byte, 0 idle, -1 EOF, -2 failure. */
int bc_sol_terminal_read(uint8_t *);
void bc_sol_terminal_close(void);
#endif
