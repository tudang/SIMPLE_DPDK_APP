/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 *
 *   ARP and ICMP handlers.
 *   Author: Huynh Tu Dang
 */

#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <getopt.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_icmp.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_arp.h>
#include <rte_log.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8192
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define MAX_PORTS 16

#define	MCAST_CLONE_PORTS	4
#define	MCAST_CLONE_SEGS	1

#define MAX_PKT_BURST 8
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

#define	HDR_MBUF_DATA_SIZE	(2 * RTE_PKTMBUF_HEADROOM)
#define	NB_HDR_MBUF	(NUM_MBUFS * MAX_PORTS)

#define	NB_CLONE_MBUF (NUM_MBUFS * MCAST_CLONE_PORTS * MCAST_CLONE_SEGS * 2)


#define RTE_LOGTYPE_PAXOS RTE_LOGTYPE_USER1

#define PAXOS_PORT 12345
struct paxos_hdr {
	uint8_t msgtype;
	uint8_t shard;
    uint16_t rnd;
    uint16_t log_index;
    uint16_t vrnd;
    uint16_t acptid;
    uint16_t reserved;
    uint32_t inst;
    uint64_t value;
    uint32_t request_id;
    uint64_t igress_ts;
} __attribute__((__packed__));

struct mbuf_table {
	uint16_t len;
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};

struct lcore_queue_conf {
	uint64_t tx_tsc;
	uint8_t rx_queue;
	uint16_t tx_queue_id;
	struct mbuf_table tx_mbufs;
} __rte_cache_aligned;
static struct lcore_queue_conf lcore_queue_conf;


static struct rte_mempool *header_pool, *clone_pool;

static struct sockaddr_in my_ip_addr;

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = ETHER_MAX_LEN,
	},
};

static struct {
	uint64_t total_cycles;
	uint64_t total_pkts;
} latency_numbers;

static void
swap_macs(struct ether_hdr *eth)
{
	struct ether_addr s_addr = eth->s_addr;
	eth->s_addr = eth->d_addr;
	eth->d_addr = s_addr;
}

static void
swap_ips(struct ipv4_hdr *ipv4)
{
	uint32_t src_addr = ipv4->src_addr;
	ipv4->src_addr = ipv4->dst_addr;
	ipv4->dst_addr = src_addr;
}

static void
swap_udp_ports(struct udp_hdr *udp)
{
	uint16_t src_port = udp->src_port;
	udp->src_port = udp->dst_port;
	udp->dst_port = src_port;
}

// static void
// print_paxos_hdr(struct paxos_hdr *paxos_hdr) {
//     RTE_LOG(DEBUG, PAXOS, "msgtype %u worker_id %u round %u inst %u log_index %u vrnd %u "
//             "acptid %u reserved %u value %s request_id %u igress_ts %"PRIu64"\n",
//                 paxos_hdr->msgtype,
//                 paxos_hdr->shard,
//                 rte_be_to_cpu_16(paxos_hdr->rnd),
//                 rte_be_to_cpu_32(paxos_hdr->inst),
//                 rte_be_to_cpu_16(paxos_hdr->log_index),
//                 rte_be_to_cpu_16(paxos_hdr->vrnd),
//                 rte_be_to_cpu_16(paxos_hdr->acptid),
//                 rte_be_to_cpu_16(paxos_hdr->reserved),
//                 (char*)&paxos_hdr->value,
//                 rte_be_to_cpu_32(paxos_hdr->request_id),
//                 rte_be_to_cpu_64(paxos_hdr->igress_ts));
// }

static void
print_paxos_hdr(struct paxos_hdr *paxos_hdr) {
    RTE_LOG(DEBUG, PAXOS, "msgtype %u worker_id %u round %u inst %u log_index %u vrnd %u "
            "acptid %u reserved %u value %s request_id %u igress_ts %"PRIu64"\n",
                paxos_hdr->msgtype,
                paxos_hdr->shard,
                (paxos_hdr->rnd),
                (paxos_hdr->inst),
                (paxos_hdr->log_index),
                (paxos_hdr->vrnd),
                (paxos_hdr->acptid),
                (paxos_hdr->reserved),
                (char*)&paxos_hdr->value,
                (paxos_hdr->request_id),
                (paxos_hdr->igress_ts));
}

static int
handle_arp(struct ether_hdr *eth_hdr, struct arp_hdr *arp_hdr, uint16_t port, uint32_t bond_ip)
{
	struct ether_addr d_addr;

	if (arp_hdr->arp_data.arp_tip == bond_ip) {
		if (arp_hdr->arp_op == rte_cpu_to_be_16(ARP_OP_REQUEST)) {
			RTE_LOG(DEBUG, PAXOS, "ARP Request\n");
			arp_hdr->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);
			/* Switch src and dst data and set bonding MAC */
			rte_eth_macaddr_get(port, &d_addr);
			ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
			ether_addr_copy(&d_addr, &eth_hdr->s_addr);
			ether_addr_copy(&arp_hdr->arp_data.arp_sha, &arp_hdr->arp_data.arp_tha);
			ether_addr_copy(&d_addr, &arp_hdr->arp_data.arp_sha);
			arp_hdr->arp_data.arp_tip = arp_hdr->arp_data.arp_sip;
			arp_hdr->arp_data.arp_sip = bond_ip;
			return  0;
		}
	}
	return -1;
}

static int
handle_icmp(struct ether_hdr *eth_hdr, struct ipv4_hdr *ipv4_hdr, struct icmp_hdr *icmp_hdr, uint32_t bond_ip)
{
	uint32_t cksum;
	if (icmp_hdr->icmp_type == IP_ICMP_ECHO_REQUEST) {
		if (ipv4_hdr->dst_addr == bond_ip) {
			icmp_hdr->icmp_type = IP_ICMP_ECHO_REPLY;
			swap_macs(eth_hdr);
			swap_ips(ipv4_hdr);
			cksum = ~icmp_hdr->icmp_cksum & 0xffff;
			cksum += ~htons(IP_ICMP_ECHO_REQUEST << 8) & 0xffff;
			cksum += htons(IP_ICMP_ECHO_REPLY << 8);
			cksum = (cksum & 0xffff) + (cksum >> 16);
			cksum = (cksum & 0xffff) + (cksum >> 16);
			icmp_hdr->icmp_cksum = ~cksum;
			return 0;
		}
	}
	return -1;
}

/* Send burst of packets on an output interface */
static void
send_burst(struct lcore_queue_conf *qconf, uint16_t port)
{
	struct rte_mbuf **m_table;
	uint16_t n, queueid;
	int ret;

	queueid = qconf->tx_queue_id;
	m_table = (struct rte_mbuf **)qconf->tx_mbufs.m_table;
	n = qconf->tx_mbufs.len;

	uint16_t i;
	for (i=0; i < n; i++) {
		RTE_LOG(DEBUG, PAXOS, "Packet %u Refcnt %u\n", i, rte_mbuf_refcnt_read(m_table[i]));
	}
	rte_mbuf_refcnt_set(m_table[n-1], 1);
	ret = rte_eth_tx_burst(port, queueid, m_table, n);
	RTE_LOG(DEBUG, PAXOS, "Request %d. SENT burst %d packets\n", n, ret);
	while (unlikely (ret < n)) {
		rte_pktmbuf_free(m_table[ret]);
		ret++;
	}

	qconf->tx_mbufs.len = 0;
}

static void
send_paxos_pkt(struct lcore_queue_conf *qconf, uint16_t port, struct rte_mbuf *pkt,
			struct ipv4_hdr *ipv4_hdr, struct udp_hdr *udp_hdr,
			struct paxos_hdr *paxos, uint8_t shard)
{
	struct paxos_hdr *px;
	px = (struct paxos_hdr *)rte_pktmbuf_append(pkt, (uint16_t)sizeof(*px));
	RTE_ASSERT(px != NULL);

	if (px != paxos) {
		rte_memcpy(px, paxos, sizeof(*paxos));
	}
	px->shard = shard;

	pkt->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;
	udp_hdr->dgram_cksum = 0;
	udp_hdr->dgram_cksum = rte_ipv4_phdr_cksum(ipv4_hdr, pkt->ol_flags);


	uint32_t len = qconf->tx_mbufs.len;
	qconf->tx_mbufs.m_table[len] = pkt;
	qconf->tx_mbufs.len = ++len;

	if (unlikely(MAX_PKT_BURST == len))
		send_burst(qconf, port);
}


static void
send_pkt(struct lcore_queue_conf *qconf, uint16_t port, struct rte_mbuf *pkt)
{
	uint32_t len = qconf->tx_mbufs.len;
	qconf->tx_mbufs.m_table[len] = pkt;
	qconf->tx_mbufs.len = ++len;

	if (unlikely(MAX_PKT_BURST == len))
		send_burst(qconf, port);
}

static inline struct rte_mbuf *
mcast_out_pkt(struct rte_mbuf *pkt)
{
	struct rte_mbuf *cloned_paxos;
	/* Create new mbuf for the header. */
	if (unlikely ((cloned_paxos = rte_pktmbuf_alloc(header_pool)) == NULL)) {
		return NULL;
	}

	if (unlikely ((pkt = rte_pktmbuf_clone(pkt, clone_pool)) == NULL)) {
		rte_pktmbuf_free(cloned_paxos);
		return NULL;
	}

	pkt->next = cloned_paxos;
	__rte_mbuf_sanity_check(pkt, 1);


	return pkt;
}

static int
handle_udp(struct lcore_queue_conf *qconf, uint8_t port, struct rte_mbuf *pkt,
	struct ether_hdr *eth_hdr, struct ipv4_hdr *ipv4_hdr, struct udp_hdr *udp_hdr,
	uint32_t bond_ip, size_t l4_offset)
{
	if (rte_be_to_cpu_16(udp_hdr->dst_port) != PAXOS_PORT)
		return -1;

	size_t paxos_offset = l4_offset + sizeof (struct udp_hdr);
	swap_macs(eth_hdr);
	swap_ips(ipv4_hdr);
	swap_udp_ports(udp_hdr);

	struct paxos_hdr *paxos = rte_pktmbuf_mtod_offset(pkt, struct paxos_hdr *, paxos_offset);
	uint8_t shard_mask = paxos->shard;

	uint16_t trim_len = sizeof(*paxos);
	if (rte_pktmbuf_trim(pkt, trim_len) < 0) {
		RTE_LOG(WARNING, PAXOS, "Failed to trim %u bytes paxos header\n", trim_len);
		return -1;
	}

	uint8_t shard;
	for (shard=0; shard_mask != 1; shard_mask >>= 1, shard++)
	{
		if ((shard_mask & 1) == 0)
			continue;

		struct rte_mbuf *mc;

		if (likely ((mc = mcast_out_pkt(pkt)) != NULL))
			send_paxos_pkt(qconf, port, mc, ipv4_hdr, udp_hdr, paxos, shard);

	}

	send_paxos_pkt(qconf, port, pkt, ipv4_hdr, udp_hdr, paxos, shard);

	return 0;
}

static int
process_packet(struct lcore_queue_conf *qconf, uint16_t port, struct rte_mbuf *pkt)
{
	struct arp_hdr *arp_hdr;
	struct ipv4_hdr *ipv4_hdr;
	struct udp_hdr *udp_hdr;
	struct icmp_hdr *icmp_hdr;

	char src[INET_ADDRSTRLEN];
	char dst[INET_ADDRSTRLEN];

	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod_offset(pkt, struct ether_hdr *, 0);
	size_t ip_offset = sizeof(struct ether_hdr);

	uint32_t bond_ip = my_ip_addr.sin_addr.s_addr;

	switch (rte_be_to_cpu_16(eth_hdr->ether_type)) {
		case ETHER_TYPE_ARP:
			arp_hdr = rte_pktmbuf_mtod_offset(pkt, struct arp_hdr *, ip_offset);
			RTE_LOG(DEBUG, PAXOS, "src=%hx dst=%hx\n", bond_ip, arp_hdr->arp_data.arp_tip);
			inet_ntop(AF_INET, &(arp_hdr->arp_data.arp_sip), src, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(arp_hdr->arp_data.arp_tip), dst, INET_ADDRSTRLEN);
			RTE_LOG(DEBUG, PAXOS, "ARP: %s -> %s\n", src, dst);
			if (!handle_arp(eth_hdr, arp_hdr, port, bond_ip))
				send_pkt(qconf, port, pkt);

		case ETHER_TYPE_IPv4:
			ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *, ip_offset);
			size_t l4_offset = ip_offset + sizeof(struct ipv4_hdr);
			inet_ntop(AF_INET, &(ipv4_hdr->src_addr), src, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(ipv4_hdr->dst_addr), dst, INET_ADDRSTRLEN);
			RTE_LOG(DEBUG, PAXOS, "IPv4: %s -> %s\n", src, dst);

			switch (ipv4_hdr->next_proto_id) {
				case IPPROTO_UDP:
					udp_hdr = rte_pktmbuf_mtod_offset(pkt, struct udp_hdr *, l4_offset);
					return handle_udp(qconf, port, pkt, eth_hdr, ipv4_hdr, udp_hdr, bond_ip, l4_offset);
				case IPPROTO_ICMP:
					icmp_hdr = rte_pktmbuf_mtod_offset(pkt, struct icmp_hdr *, l4_offset);
					RTE_LOG(DEBUG, PAXOS, "ICMP: %s -> %s: Type: %02x\n", src, dst, icmp_hdr->icmp_type);
					if (!handle_icmp(eth_hdr, ipv4_hdr, icmp_hdr, bond_ip))
						send_pkt(qconf, port, pkt);
				default:
					RTE_LOG(DEBUG, PAXOS, "IP Proto: %d\n", ipv4_hdr->next_proto_id);
					return -1;
			}
			break;
		default:
			RTE_LOG(DEBUG, PAXOS, "Ether Proto: 0x%04x\n", rte_be_to_cpu_16(eth_hdr->ether_type));
			return -1;
	}
	return -1;
}

static uint16_t
add_timestamps(uint16_t port __rte_unused, uint16_t qidx __rte_unused,
		struct rte_mbuf **pkts, uint16_t nb_pkts,
		uint16_t max_pkts __rte_unused, void *arg)
{
	struct lcore_queue_conf *qconf = arg;
	unsigned i;
	int ret = 0;
	uint64_t now = rte_rdtsc();
	uint16_t nb_rx = nb_pkts;
	for (i = 0; i < nb_rx; i++) {
		pkts[i]->udata64 = now;
		ret = process_packet(qconf, port, pkts[i]);
		if (ret < 0) {
			rte_pktmbuf_free(pkts[i]);
			nb_pkts--;
		}
	}
	return nb_pkts;
}

static uint16_t
calc_latency(uint16_t port __rte_unused, uint16_t qidx __rte_unused,
		struct rte_mbuf **pkts, uint16_t nb_pkts, void *_ __rte_unused)
{
	uint64_t cycles = 0;
	uint64_t now = rte_rdtsc();
	unsigned i;

	for (i = 0; i < nb_pkts; i++)
		cycles += now - pkts[i]->udata64;
	latency_numbers.total_cycles += cycles;
	latency_numbers.total_pkts += nb_pkts;

	if (latency_numbers.total_pkts > (100 * 1000 * 1000ULL)) {
		printf("Latency = %"PRIu64" cycles\n",
		latency_numbers.total_cycles / latency_numbers.total_pkts);
		latency_numbers.total_cycles = latency_numbers.total_pkts = 0;
	}
	return nb_pkts;
}

/*
 * Initialises a given port using global settings and with the rx buffers
 * coming from the mbuf_pool passed as parameter
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct lcore_queue_conf *qconf;
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	qconf = &lcore_queue_conf;
	qconf->rx_queue = port;

	rte_eth_dev_info_get(port, &dev_info);
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

		port_conf.txmode.offloads =
	        (DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM |
	         DEV_TX_OFFLOAD_TCP_CKSUM);
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	qconf->tx_queue_id = 0;

	retval  = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	struct ether_addr addr;

	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02"PRIx8" %02"PRIx8" %02"PRIx8
			" %02"PRIx8" %02"PRIx8" %02"PRIx8"\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	rte_eth_promiscuous_enable(port);
	rte_eth_add_rx_callback(port, 0, add_timestamps, qconf);
	rte_eth_add_tx_callback(port, 0, calc_latency, NULL);

	return 0;
}

/* Send burst of outgoing packet, if timeout expires. */
static inline void
send_timeout_burst(struct lcore_queue_conf *qconf)
{
	uint64_t cur_tsc;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

	cur_tsc = rte_rdtsc();
	if (likely (cur_tsc < qconf->tx_tsc + drain_tsc))
		return;

	if (qconf->tx_mbufs.len != 0) {
		RTE_LOG(INFO, PAXOS, "Timeout flush\n");
		send_burst(qconf, qconf->tx_queue_id);
	}

	qconf->tx_tsc = cur_tsc;
}


/*
 * Main thread that does the work, reading from INPUT_PORT
 * and writing to OUTPUT_PORT
 */
static  __attribute__((noreturn)) void
lcore_main(void)
{
	uint16_t port;

	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());
	for (;;) {
		RTE_ETH_FOREACH_DEV(port) {
			struct rte_mbuf *bufs[BURST_SIZE];
			rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
			send_timeout_burst(&lcore_queue_conf);
		}
	}
}

static int
parse_arg_ip_address(const char *arg, struct sockaddr_in *addr)
{
    int ret;
    char* ip_and_port = strdup(arg);
    const char delim[2] = ":";
    char* token = strtok(ip_and_port, delim);
    addr->sin_family = AF_INET;
    if (token != NULL) {
        ret = inet_pton(AF_INET, token, &addr->sin_addr);
        if (ret == 0 || ret < 0) {
            return -1;
        }
    }
    token = strtok(NULL, delim);
    if (token != NULL) {
        uint32_t x;
        char* endpt;
        errno = 0;
        x = strtoul(token, &endpt, 10);
        if (errno != 0 || endpt == arg || *endpt != '\0') {
          return -2;
        }
        addr->sin_port = htons(x);
    }

	char *ip = inet_ntoa(addr->sin_addr);
	RTE_LOG(DEBUG, PAXOS, "SRC %s\n", ip);
    return 0;
}

static
int app_parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{"src", 1, 0, 0},
		{NULL, 0, 0, 0}
	};
	uint32_t argc_src = 0;
	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "", lgopts, &option_index)) != EOF) {
		switch (opt) {
			case 0:
				if (!strcmp(lgopts[option_index].name, "src")) {
					argc_src = 1;
					ret = parse_arg_ip_address(optarg, &my_ip_addr);
					if (ret) {
						printf("Incorrect value for --src argument (%d)\n", ret);
						return -1;
					}
				}
				break;
			default:
				ret = -1;
		}
	}

	if (argc_src == 0)
	{
		ret = parse_arg_ip_address("192.168.4.96:12345", &my_ip_addr);
	}
	if (optind >= 0)
		argv[optind - 1] = prgname;

	ret = optind - 1;
	optind = 1; /* reset getopt lib */
	return ret;
}

/* Main function, does initialisation and calls the per-lcore functions */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	uint16_t nb_ports;
	uint16_t portid;

	/* init EAL */
	int ret = rte_eal_init(argc, argv);

	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	argc -= ret;
	argv += ret;

	ret = app_parse_args(argc, argv);
	argc -= ret;
	argv += ret;

	rte_log_set_level(RTE_LOGTYPE_PAXOS, rte_log_get_global_level());

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 1)
		rte_exit(EXIT_FAILURE, "Error: number of ports must be greater than 0\n");

	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
		NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
		RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	header_pool = rte_pktmbuf_pool_create("header_pool", NB_HDR_MBUF, 32,
		0, HDR_MBUF_DATA_SIZE, rte_socket_id());

	if (header_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init header mbuf pool\n");

	clone_pool = rte_pktmbuf_pool_create("clone_pool", NB_CLONE_MBUF, 32,
		0, 0, rte_socket_id());

	if (clone_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init clone mbuf pool\n");

	/* initialize all ports */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8"\n",
					portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too much enabled lcores - "
			"App uses only 1 lcore\n");

	/* call lcore_main on master core only */
	lcore_main();
	return 0;
}
