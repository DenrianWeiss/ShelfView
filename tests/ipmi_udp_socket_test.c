#include "../platform/ipmi_udp.c"
#include <assert.h>
#include <signal.h>
#include <sys/wait.h>

int main(void) {
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        assert(signal(SIGPIPE, SIG_DFL) != SIG_ERR);
        bc_ipmi_io *io = NULL;
        assert(bc_ipmi_udp_create((bc_string){"127.0.0.1", 9}, 623, &io) == BC_OK);
        udp_transport *udp = io->userdata;
        assert(!shutdown(udp->socket, SHUT_WR));
        const uint8_t data = 0;
        assert(io->send(io->userdata, &data, 1) == BC_IO_ERROR);
        struct sigaction action;
        assert(!sigaction(SIGPIPE, NULL, &action) && action.sa_handler == SIG_DFL);
        bc_ipmi_udp_destroy(io);
        _exit(0);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    if (WIFSIGNALED(status)) fprintf(stderr, "UDP sender terminated by signal %d\n", WTERMSIG(status));
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}
