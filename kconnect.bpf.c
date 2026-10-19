/* Dummy struct to fix BCC compilation on newer kernels */
struct bpf_wq {};

#include <uapi/linux/ptrace.h>  
#include <net/sock.h>           
#include <linux/in.h>           
#include <linux/in6.h>           

struct event_t {
    u32  pid;           

    u32  uid;           

    char comm[16];      

    u32  saddr;         

    u32  daddr;         

    u8   saddr6[16];    
    u8   daddr6[16];    

    u16  sport;         

    u16  dport;         

    u8   proto;         

    u8   is_ipv6;       
};

struct conn_key_t {

    u32  pid;
    u32  daddr;         
    u8   daddr6[16];    
    u16  dport;
    u8   proto;
    u8   pad;           
};

BPF_PERF_OUTPUT(events);

BPF_HASH(seen, struct conn_key_t, u8);

static __always_inline int is_new_conn(u32 pid, u32 daddr,
                                        u8 *daddr6, u16 dport, u8 proto)
{
    struct conn_key_t k = {};   
    k.pid   = pid;
    k.daddr = daddr;
    k.dport = dport;
    k.proto = proto;

    if (daddr6) {

        bpf_probe_read_kernel(&k.daddr6, 16, daddr6);
    }

    if (seen.lookup(&k)) return 0;     

    u8 one = 1;
    seen.insert(&k, &one);             
    return 1;                          
}

static __always_inline void fill_and_submit(struct pt_regs *ctx,
                                             struct sock *sk, u8 proto)
{

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid == 0) return;

    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);

    struct event_t e = {};  
    e.pid   = pid;
    e.uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;  
    e.proto = proto;

    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    e.sport = sk->__sk_common.skc_num;

    u16 dp = 0;
    bpf_probe_read_kernel(&dp, sizeof(dp), &sk->__sk_common.skc_dport);
    e.dport = ntohs(dp);

    if (family == AF_INET) {

        bpf_probe_read_kernel(&e.daddr, sizeof(e.daddr),
                              &sk->__sk_common.skc_daddr);
        bpf_probe_read_kernel(&e.saddr, sizeof(e.saddr),
                              &sk->__sk_common.skc_rcv_saddr);

        if (e.daddr == 0) return;

        if (!is_new_conn(pid, e.daddr, NULL, e.dport, proto)) return;

        e.is_ipv6 = 0;

    } else if (family == AF_INET6) {

        bpf_probe_read_kernel(&e.daddr6, sizeof(e.daddr6),
                              &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
        bpf_probe_read_kernel(&e.saddr6, sizeof(e.saddr6),
                              &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);

        if (!is_new_conn(pid, 0, e.daddr6, e.dport, proto)) return;

        e.is_ipv6 = 1;

    } else {
        return;  
    }

    events.perf_submit(ctx, &e, sizeof(e));
}

int trace_tcp4(struct pt_regs *ctx, struct sock *sk)
{
    fill_and_submit(ctx, sk, IPPROTO_TCP);
    return 0;  
}

int trace_tcp6(struct pt_regs *ctx, struct sock *sk,
               struct sockaddr *uaddr, int addr_len)
{
    fill_and_submit(ctx, sk, IPPROTO_TCP);
    return 0;
}

int trace_udp4(struct pt_regs *ctx, struct sock *sk,
               struct msghdr *msg, size_t len)
{
    fill_and_submit(ctx, sk, IPPROTO_UDP);
    return 0;
}

int trace_udp6(struct pt_regs *ctx, struct sock *sk,
               struct msghdr *msg, size_t len)
{
    fill_and_submit(ctx, sk, IPPROTO_UDP);
    return 0;
}
