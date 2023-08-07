#ifndef __COOKIE_H__
#define __COOKIE_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

static __always_inline u32 get_sk_cookie(struct sock *sk) {
    __u64 t = bpf_ktime_get_ns();
    __u64 _sk = 0;
    bpf_probe_read_kernel(&_sk, sizeof(_sk), &sk);
    return (u32)(_sk ^ t);
}

#endif // __COOKIE_H__
