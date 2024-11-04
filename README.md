# checksum

A library for calculating packet checksums, can also be applied when csum offloading is available

## How to use

```c
// calculate all checksums:
vproxy_pkt_ether_csum(pkt, pktlen, VPROXY_CSUM_ALL);

// calculate ip checksum and pseudo header checksum for upper layer protocols:
vproxy_pkt_ether_csum(pkt, pktlen, VPROXY_CSUM_UP_PSEUDO);

// calculate tcp checksum when iphdr and tcphdr location already known
struct vproxy_csum_out out;
vproxy_pkt_tcp4_csum(ipp, tcpp, tcplen, VPROXY_CSUM_ALL, &out);
```
