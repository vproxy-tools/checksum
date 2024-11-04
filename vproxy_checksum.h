#ifndef VPROXY_CHECKSUM_H
#define VPROXY_CHECKSUM_H

#define VPROXY_CSUM_NO        (0)
#define VPROXY_CSUM_IP        (1 << 0)
#define VPROXY_CSUM_UP        (1 << 1)
#define VPROXY_CSUM_UP_PSEUDO (1 << 2)

#define VPROXY_CSUM_ALL (VPROXY_CSUM_UP | VPROXY_CSUM_IP)

struct vproxy_csum_out {
    char* up_pos;
    char* up_csum_pos;
};

static inline int vproxy_csum_calc0(int sum, char* data, int len) {
    for (int i = 0; i < len / 2; ++i) {
        sum += ((data[2 * i] & 0xff) << 8) | (data[2 * i + 1] & 0xff);
        while (sum > 0xffff) {
            sum = (sum & 0xffff) + 1;
        }
    }
    if (len % 2 != 0) {
        sum += ((data[len - 1] & 0xff) << 8);
        while (sum > 0xffff) {
            sum = (sum & 0xffff) + 1;
        }
    }
    return sum;
}

static inline int vproxy_csum_plain_calc(char* data, int len) {
    int n = vproxy_csum_calc0(0, data, len);
    return 0xffff - n;
}

static inline int vproxy_csum_ipv4_pseudo_calc(char* src, char* dst, char proto, char* data, int datalen) {
    int sum = vproxy_csum_calc0(0, src, 4);
    sum = vproxy_csum_calc0(sum, dst, 4);
    char foo[2];
    foo[0] = 0;
    foo[1] = proto;
    sum = vproxy_csum_calc0(sum, foo, 2);
    foo[0] = (datalen >> 8) & 0xff;
    foo[1] = datalen & 0xff;
    sum = vproxy_csum_calc0(sum, foo, 2);
    sum = vproxy_csum_calc0(sum, data, datalen);
    return 0xffff - sum;
}

static inline int vproxy_csum_ipv6_pseudo_calc(char* src, char* dst, char proto, char* data, int datalen) {
    int sum = vproxy_csum_calc0(0, src, 16);
    sum = vproxy_csum_calc0(sum, dst, 16);
    char foo[4];
    foo[0] = (datalen >> 24) & 0xff;
    foo[1] = (datalen >> 16) & 0xff;
    foo[2] = (datalen >> 8) & 0xff;
    foo[3] = datalen & 0xff;
    sum = vproxy_csum_calc0(sum, foo, 4);
    foo[0] = 0;
    foo[1] = 0;
    foo[2] = 0;
    foo[3] = proto;
    sum = vproxy_csum_calc0(sum, foo, 4);
    sum = vproxy_csum_calc0(sum, data, datalen);
    return 0xffff - sum;
}

int vproxy_pkt_ether_csum_ex(char* raw, int len, int flags, struct vproxy_csum_out* out);
int vproxy_pkt_ether_csum(          char* raw, int len, int flags);
int vproxy_pkt_ipv4_csum (          char* raw, int len, int flags, struct vproxy_csum_out* out);
int vproxy_pkt_icmp4_csum(          char* raw, int len, int flags, struct vproxy_csum_out* out);
int vproxy_pkt_tcp4_csum (char* ip, char* raw, int len, int flags, struct vproxy_csum_out* out);
int vproxy_pkt_udp4_csum (char* ip, char* raw, int len, int flags, struct vproxy_csum_out* out);
int vproxy_pkt_ipv6_csum (          char* raw, int len, int flags, struct vproxy_csum_out* out);
int vproxy_pkt_icmp6_csum(char* ip, char* raw, int len, int flags, struct vproxy_csum_out* out);
int vproxy_pkt_tcp6_csum (char* ip, char* raw, int len, int flags, struct vproxy_csum_out* out);
int vproxy_pkt_udp6_csum (char* ip, char* raw, int len, int flags, struct vproxy_csum_out* out);

char* vproxy_pkt_ipv6_skip_to_last_hdr(char* raw, int len, char* proto);

#endif
