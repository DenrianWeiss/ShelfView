#include "sol_cmd.h"
#include "sol_terminal.h"
#include "server.h"
#include "bcontrol/ipmi_sol.h"
#include <stdio.h>
#include <signal.h>
static volatile sig_atomic_t stopped;
static void stop(int number) { (void)number; stopped = 1; }
int bc_agent_sol_run(bc_ipmi_session *session, uint16_t port, bc_agent_ipmi_budget *budget) {
    bc_ipmi_sol_options options = {0};
    options.struct_size = sizeof(options); options.abi_version = BC_ABI_VERSION;
    options.session_port = port; options.retries = 3;
    bc_ipmi_sol *sol = NULL;
    bc_status status = bc_ipmi_sol_open(session, &options, bc_agent_now_ms(), &sol);
    bc_serial_stream *stream = NULL;
    if (status == BC_OK) status = bc_ipmi_sol_stream(sol, &stream);
    if (status == BC_OK) bc_agent_ipmi_budget_unlimit(budget);
    int terminal = 0, eof = 0, escape = 0, line_start = 1;
    uint8_t pending[2]; uint32_t pending_length = 0;
    void (*old_int)(int) = signal(SIGINT, stop), (*old_term)(int) = signal(SIGTERM, stop);
#ifdef SIGPIPE
    void (*old_pipe)(int) = signal(SIGPIPE, SIG_IGN);
#endif
    stopped = 0;
    if (status == BC_OK) {
        terminal = bc_sol_terminal_open();
        if (!terminal) status = BC_IO_ERROR;
        else fputs("SOL connected; at line start ~. exits, ~~ sends ~, ~B sends Break.\n", stderr);
    }
    while (status == BC_OK && !stopped) {
        if (!eof && !pending_length) {
            uint8_t byte; int result = bc_sol_terminal_read(&byte);
            if (result == -2) { status = BC_IO_ERROR; break; }
            if (result == -1) { eof = 1; if (escape) { pending[0] = '~'; pending_length = 1; escape = 0; } }
            if (result == 1) {
                if (escape) {
                    escape = 0;
                    if (byte == '.') { eof = 1; }
                    else if (byte == 'B') { bc_status s = bc_serial_control(stream, BC_SERIAL_CONTROL_BREAK); if (s != BC_OK) fputs("SOL Break unavailable while input is pending.\n", stderr); }
                    else { if (byte != '~') pending[pending_length++] = '~'; pending[pending_length++] = byte; }
                } else if (line_start && byte == '~') escape = 1;
                else pending[pending_length++] = byte;
                if (!escape) line_start = byte == '\r' || byte == '\n';
            }
        }
        if (pending_length) {
            uint32_t accepted = 0;
            status = bc_serial_write(stream, (bc_bytes){pending, pending_length}, &accepted);
            if (status == BC_BUSY) status = BC_OK;
            if (accepted < pending_length) pending[0] = pending[accepted];
            pending_length -= accepted;
        }
        if (status != BC_OK) break;
        uint8_t output[4096]; uint32_t length = 0;
        status = bc_serial_read(stream, bc_agent_now_ms(), 10, output, sizeof(output), &length);
        if (status == BC_TIMEOUT) status = BC_OK;
        if (length && (fwrite(output, 1, length, stdout) != length || fflush(stdout))) status = BC_IO_ERROR;
        bc_serial_info info = {0}; info.struct_size = sizeof(info);
        bc_status info_status = bc_serial_info_get(stream, &info);
        if (status == BC_OK) status = info_status;
        if (eof && !pending_length && !(info.protocol_flags & BC_IPMI_SOL_INPUT_PENDING)) break;
    }
    if (terminal) bc_sol_terminal_close();
    signal(SIGINT, old_int); signal(SIGTERM, old_term);
#ifdef SIGPIPE
    signal(SIGPIPE, old_pipe);
#endif
    bc_agent_ipmi_budget_cleanup(budget);
    bc_status cleanup = BC_OK;
    if (sol) {
        if (stream) bc_serial_close(stream);
        else bc_ipmi_sol_close(sol);
        bc_ipmi_sol_info info = {0}; info.struct_size = sizeof(info); bc_ipmi_sol_info_get(sol, &info);
        cleanup = info.cleanup_status;
        if (status == BC_OK && info.status != BC_OK) status = info.status;
        bc_serial_destroy(stream);
        bc_ipmi_sol_destroy(sol);
    }
    fprintf(stderr, "SOL status=%s cleanup=%s\n", bc_status_string(status), bc_status_string(cleanup));
    return status == BC_OK && cleanup == BC_OK ? 0 : 1;
}
