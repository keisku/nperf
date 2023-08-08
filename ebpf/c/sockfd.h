#ifndef __SOCKFD_H
#define __SOCKFD_H

#include "vmlinux.h"
#include "map_defs.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

typedef struct
{
    __u32 pid;
    __u32 fd;
} pid_fd_t;

// This map is used to to temporarily store function arguments (sockfd) for
// sockfd_lookup_light function calls, so they can be accessed by the corresponding kretprobe.
// * Key is the pid_tgid;
// * Value the socket FD;
BPF_HASH_MAP(sockfd_lookup_args, __u64, __u32, 1024)

BPF_HASH_MAP(sock_by_pid_fd, pid_fd_t, struct sock *, 1024)

BPF_HASH_MAP(pid_fd_by_sock, struct sock *, pid_fd_t, 1024)

static __always_inline void clear_sockfd_maps(struct sock *sock) {
    if (sock == NULL) {
        return;
    }

    pid_fd_t *pid_fd = bpf_map_lookup_elem(&pid_fd_by_sock, &sock);
    if (pid_fd == NULL) {
        return;
    }

    // Copy map value to stack before re-using it (needed for Kernel 4.4)
    pid_fd_t pid_fd_copy = {};
    pid_fd = &pid_fd_copy;

    bpf_map_delete_elem(&sock_by_pid_fd, pid_fd);
    bpf_map_delete_elem(&pid_fd_by_sock, &sock);
}

#endif // __SOCKFD_H
