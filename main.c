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

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define RTE_LOGTYPE_PAXOS RTE_LOGTYPE_USER1

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

static int
process_packet(uint16_t port, struct rte_mbuf *pkt)
{
	struct arp_hdr *arp_hdr;
	struct ipv4_hdr *ipv4_hdr;
	struct udp_hdr *udp_hdr;
	struct icmp_hdr *icmp_hdr;
	int ret = 0;
	char src[INET_ADDRSTRLEN];
	char dst[INET_ADDRSTRLEN];

	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod_offset(pkt, struct ether_hdr *, 0);
	size_t ip_offset = sizeof(struct ether_hdr);

	struct ether_addr d_addr;
	uint32_t bond_ip = my_ip_addr.sin_addr.s_addr;

	switch (rte_be_to_cpu_16(eth_hdr->ether_type)) {
		case ETHER_TYPE_ARP:
			arp_hdr = rte_pktmbuf_mtod_offset(pkt, struct arp_hdr *, ip_offset);
			RTE_LOG(DEBUG, PAXOS, "src=%hx dst=%hx\n", bond_ip, arp_hdr->arp_data.arp_tip);

			inet_ntop(AF_INET, &(arp_hdr->arp_data.arp_sip), src, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(arp_hdr->arp_data.arp_tip), dst, INET_ADDRSTRLEN);
			RTE_LOG(DEBUG, PAXOS, "ARP: %s -> %s\n", src, dst);
			if (arp_hdr->arp_data.arp_tip == bond_ip) {
				if (arp_hdr->arp_op == rte_cpu_to_be_16(ARP_OP_REQUEST)) {
					RTE_LOG(DEBUG, PAXOS, "ARP Request\n");
					arp_hdr->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);
					/* Switch src and dst data and set bonding MAC */
					ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
					rte_eth_macaddr_get(port, &eth_hdr->s_addr);
					ether_addr_copy(&arp_hdr->arp_data.arp_sha, &arp_hdr->arp_data.arp_tha);
					arp_hdr->arp_data.arp_tip = arp_hdr->arp_data.arp_sip;
					rte_eth_macaddr_get(port, &d_addr);
					ether_addr_copy(&d_addr, &arp_hdr->arp_data.arp_sha);
					arp_hdr->arp_data.arp_sip = bond_ip;
					ret = 0;
				}
			} else {
				ret = -1;
			}
			break;
		case ETHER_TYPE_IPv4:
			ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *, ip_offset);
			size_t l4_offset = ip_offset + sizeof(struct ipv4_hdr);
			inet_ntop(AF_INET, &(ipv4_hdr->src_addr), src, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(ipv4_hdr->dst_addr), dst, INET_ADDRSTRLEN);

			RTE_LOG(DEBUG, PAXOS, "IPv4: %s -> %s\n", src, dst);

			switch (ipv4_hdr->next_proto_id) {
				case IPPROTO_UDP:
					udp_hdr = rte_pktmbuf_mtod_offset(pkt, struct udp_hdr *, l4_offset);
					ret = udp_hdr->dst_port;
					break;
				case IPPROTO_ICMP:
					icmp_hdr = rte_pktmbuf_mtod_offset(pkt, struct icmp_hdr *, l4_offset);
					RTE_LOG(DEBUG, PAXOS, "ICMP: %s -> %s: Type: %02x\n", src, dst, icmp_hdr->icmp_type);
					if (icmp_hdr->icmp_type == IP_ICMP_ECHO_REQUEST) {
						if (ipv4_hdr->dst_addr == bond_ip) {
							icmp_hdr->icmp_type = IP_ICMP_ECHO_REPLY;
							ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
							rte_eth_macaddr_get(port, &eth_hdr->s_addr);
							ipv4_hdr->dst_addr = ipv4_hdr->src_addr;
							ipv4_hdr->src_addr = bond_ip;
							ret = 0;
						}
					}
					break;
				default:
					ret = -1;
					RTE_LOG(DEBUG, PAXOS, "IP Proto: %d\n", ipv4_hdr->next_proto_id);
					break;
			}
			break;
		default:
			RTE_LOG(DEBUG, PAXOS, "Ether Proto: 0x%04x\n", rte_be_to_cpu_16(eth_hdr->ether_type));
			ret = -1;
			break;
	}
	return ret;
}

static uint16_t
add_timestamps(uint16_t port __rte_unused, uint16_t qidx __rte_unused,
		struct rte_mbuf **pkts, uint16_t nb_pkts,
		uint16_t max_pkts __rte_unused, void *_ __rte_unused)
{
	unsigned i;
	int ret = 0;
	uint64_t now = rte_rdtsc();
	uint16_t nb_rx = nb_pkts;
	for (i = 0; i < nb_rx; i++) {
		pkts[i]->udata64 = now;
		ret = process_packet(port, pkts[i]);
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

	rte_eth_dev_info_get(port, &dev_info);
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

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
	rte_eth_add_rx_callback(port, 0, add_timestamps, NULL);
	rte_eth_add_tx_callback(port, 0, calc_latency, NULL);

	return 0;
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
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);
			if (unlikely(nb_rx == 0))
				continue;

			const uint16_t nb_tx = rte_eth_tx_burst(port, 0,
					bufs, nb_rx);
			RTE_LOG(DEBUG, PAXOS, "Sent %u packets\n", nb_tx);

			if (unlikely(nb_tx < nb_rx)) {
				uint16_t buf;
				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(bufs[buf]);
			}
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
