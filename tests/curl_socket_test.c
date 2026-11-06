#include "../platform/curl_socket.h"
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
static void disconnected(int protect) {
    int pair[2]; assert(!socketpair(AF_UNIX,SOCK_STREAM,0,pair));
    assert(signal(SIGPIPE,SIG_DFL) != SIG_ERR);
    if (protect) {
        assert(bc_curl_socket_options(NULL,pair[0],CURLSOCKTYPE_IPCXN) == CURL_SOCKOPT_OK);
        int enabled = 0; socklen_t size = sizeof(enabled);
        assert(!getsockopt(pair[0],SOL_SOCKET,SO_NOSIGPIPE,&enabled,&size) && enabled);
    }
    close(pair[1]); errno = 0;
    assert(send(pair[0],"x",1,0) == -1 && errno == EPIPE);
    struct sigaction action; assert(!sigaction(SIGPIPE,NULL,&action) && action.sa_handler == SIG_DFL);
    close(pair[0]);
}
int main(void) {
    for (int protect = 0; protect <= 1; ++protect) {
        pid_t child = fork(); assert(child >= 0);
        if (!child) { disconnected(protect); _exit(0); }
        int status = 0; assert(waitpid(child,&status,0) == child);
        if (protect) assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        else assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGPIPE);
    }
    assert(bc_curl_socket_options(NULL,-1,CURLSOCKTYPE_IPCXN) == CURL_SOCKOPT_ERROR);
    return 0;
}
