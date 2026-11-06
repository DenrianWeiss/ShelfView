#define _POSIX_C_SOURCE 200809L
#include "sol_terminal.h"
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <io.h>
#include <fcntl.h>
static DWORD input_mode, output_mode;
static int changed_input, changed_output, binary_input = -1, binary_output = -1;
static UINT input_cp, output_cp;
static uint8_t pending[256];
static DWORD pending_length, pending_offset;
int bc_sol_terminal_open(void) {
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE), out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (GetConsoleMode(in, &input_mode)) {
        if (!SetConsoleMode(in, (input_mode & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT)) | ENABLE_VIRTUAL_TERMINAL_INPUT)) return 0;
        changed_input = 1;
        input_cp = GetConsoleCP();
        if (!SetConsoleCP(CP_UTF8)) { bc_sol_terminal_close(); return 0; }
    }
    if (GetConsoleMode(out, &output_mode)) {
        if (!SetConsoleMode(out, output_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) { bc_sol_terminal_close(); return 0; }
        changed_output = 1;
        output_cp = GetConsoleOutputCP();
        if (!SetConsoleOutputCP(CP_UTF8)) { bc_sol_terminal_close(); return 0; }
    }
    binary_input = _setmode(0, _O_BINARY); binary_output = _setmode(1, _O_BINARY);
    if (binary_input < 0 || binary_output < 0) { bc_sol_terminal_close(); return 0; }
    return 1;
}
int bc_sol_terminal_read(uint8_t *byte) {
    if (pending_offset < pending_length) { *byte = pending[pending_offset++]; return 1; }
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE); DWORD mode, ready = 0;
    if (GetConsoleMode(in, &mode)) {
        /* Ignore non-key console records so ReadFile cannot block on resize. */
        INPUT_RECORD record; DWORD count;
        if (!PeekConsoleInputW(in, &record, 1, &count)) return -2;
        if (!count) return 0;
        WORD key = record.EventType == KEY_EVENT ? record.Event.KeyEvent.wVirtualKeyCode : 0;
        if (record.EventType != KEY_EVENT || !record.Event.KeyEvent.bKeyDown || key == VK_SHIFT || key == VK_CONTROL ||
            key == VK_MENU || key == VK_CAPITAL || key == VK_NUMLOCK || key == VK_SCROLL || key == VK_LWIN || key == VK_RWIN) {
            ReadConsoleInputW(in, &record, 1, &count); return 0;
        }
    } else if (GetFileType(in) == FILE_TYPE_PIPE) {
        if (!PeekNamedPipe(in, NULL, 0, NULL, &ready, NULL)) return GetLastError() == ERROR_BROKEN_PIPE ? -1 : -2;
        if (!ready) return 0;
    }
    pending_offset = pending_length = 0;
    if (!ReadFile(in, pending, sizeof(pending), &pending_length, NULL)) return -2;
    if (!pending_length) return -1;
    *byte = pending[pending_offset++]; return 1;
}
void bc_sol_terminal_close(void) {
    if (binary_input >= 0) { _setmode(0, binary_input); binary_input = -1; }
    if (binary_output >= 0) { _setmode(1, binary_output); binary_output = -1; }
    if (changed_input) { SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), input_mode); changed_input = 0; }
    if (changed_output) { SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), output_mode); changed_output = 0; }
    if (input_cp) { SetConsoleCP(input_cp); input_cp = 0; }
    if (output_cp) { SetConsoleOutputCP(output_cp); output_cp = 0; }
    pending_offset = pending_length = 0;
}
#else
#include <termios.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
static struct termios saved;
static int changed;
int bc_sol_terminal_open(void) {
    if (!isatty(STDIN_FILENO)) return 1;
    if (tcgetattr(STDIN_FILENO, &saved)) return 0;
    struct termios raw = saved;
    raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    raw.c_oflag &= ~OPOST;
    raw.c_cflag = (raw.c_cflag & ~(CSIZE | PARENB)) | CS8;
    raw.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
    raw.c_cc[VMIN] = 1; raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw)) return 0;
    changed = 1; return 1;
}
int bc_sol_terminal_read(uint8_t *byte) {
    struct pollfd fd = {STDIN_FILENO, POLLIN, 0};
    int ready = poll(&fd, 1, 0);
    if (ready < 0) return errno == EINTR ? 0 : -2;
    if (!ready) return 0;
    ssize_t n = read(STDIN_FILENO, byte, 1);
    return n == 1 ? 1 : n == 0 ? -1 : errno == EINTR ? 0 : -2;
}
void bc_sol_terminal_close(void) {
    if (changed) { tcsetattr(STDIN_FILENO, TCSANOW, &saved); changed = 0; }
}
#endif
