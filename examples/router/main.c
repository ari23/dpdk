/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define MAX_PKT_BURST 512
#define RTE_BE_TO_CPU_16(be_16_v) \
	(uint16_t)((((be_16_v)&0xFF) << 8) | ((be_16_v) >> 8))

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
	},
};

/* main.c: Basic DPDK skeleton router */
/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
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

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;

	return 0;
}

static const char *
arp_op_name(uint16_t arp_op)
{
	switch (arp_op)
	{
	case RTE_ARP_OP_REQUEST:
		return "ARP Request";
	case RTE_ARP_OP_REPLY:
		return "ARP Reply";
	case RTE_ARP_OP_REVREQUEST:
		return "Reverse ARP Request";
	case RTE_ARP_OP_REVREPLY:
		return "Reverse ARP Reply";
	case RTE_ARP_OP_INVREQUEST:
		return "Peer Identify Request";
	case RTE_ARP_OP_INVREPLY:
		return "Peer Identify Reply";
	default:
		break;
	}
	return "Unkwown ARP op";
}

static void
ether_addr_dump(const char *what, const struct rte_ether_addr *ea)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];

	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, ea);
	if (what)
		printf("%s", what);
	printf("%s", buf);
}

static void
ipv4_addr_to_dot(uint32_t be_ipv4_addr, char *buf)
{
	uint32_t ipv4_addr;

	ipv4_addr = rte_be_to_cpu_32(be_ipv4_addr);
	sprintf(buf, "%d.%d.%d.%d", (ipv4_addr >> 24) & 0xFF,
			(ipv4_addr >> 16) & 0xFF, (ipv4_addr >> 8) & 0xFF,
			ipv4_addr & 0xFF);
}

static void
ipv4_addr_dump(const char *what, uint32_t be_ipv4_addr)
{
	char buf[16];

	ipv4_addr_to_dot(be_ipv4_addr, buf);
	if (what)
		printf("%s", what);
	printf("%s", buf);
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static __attribute__((noreturn)) void
lcore_main(void)
{
	uint16_t port;
	uint8_t i;
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *pkt;
	struct rte_ether_hdr *eth_h;
	struct rte_arp_hdr *arp_h;
	struct rte_ether_addr eth_addr;

	uint32_t ip_addr;
	uint16_t arp_op;
	uint16_t arp_pro;
	uint16_t eth_type;
	uint16_t nb_replies = 0;
	int l2_len, retval;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

	/* Run until the application is quit or killed. */
	for (;;) {
		/*
		 * Receive packets on a port and forward them on the paired
		 * port. The mapping is 0 -> 1, 1 -> 0, 2 -> 3, 3 -> 2, etc.
		 */
		RTE_ETH_FOREACH_DEV(port) {

			/* Get burst of RX packets, from first port of pair. */
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					pkts_burst, MAX_PKT_BURST);

			if (unlikely(nb_rx == 0))
				continue;

			for (i = 0; i < nb_rx; i++) {
				if (likely(i < nb_rx - 1))
					rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[i + 1], void *));

				pkt = pkts_burst[i];
				eth_h = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
				eth_type = RTE_BE_TO_CPU_16(eth_h->ether_type);
				l2_len = sizeof(struct rte_ether_hdr);

				printf("\nPort %d pkt-len=%u nb-segs=%u\n",
					   port, pkt->pkt_len, pkt->nb_segs);
				ether_addr_dump("  ETH:  src=", &eth_h->s_addr);
				ether_addr_dump(" dst=", &eth_h->d_addr);

				/* Reply to ARP requests */
				if (eth_type == RTE_ETHER_TYPE_ARP)
				{
					arp_h = (struct rte_arp_hdr *)((char *)eth_h + l2_len);
					arp_op = RTE_BE_TO_CPU_16(arp_h->arp_opcode);
					arp_pro = RTE_BE_TO_CPU_16(arp_h->arp_protocol);
					printf("\n");
					printf("  ARP:  hrd=%d proto=0x%04x hln=%d "
						   "pln=%d op=%u (%s)\n",
						   RTE_BE_TO_CPU_16(arp_h->arp_hardware),
						   arp_pro, arp_h->arp_hlen,
						   arp_h->arp_plen, arp_op,
						   arp_op_name(arp_op));

					if ((RTE_BE_TO_CPU_16(arp_h->arp_hardware) !=
						 RTE_ARP_HRD_ETHER) ||
						(arp_pro != RTE_ETHER_TYPE_IPV4) ||
						(arp_h->arp_hlen != 6) ||
						(arp_h->arp_plen != 4))
					{
						rte_pktmbuf_free(pkt);
						printf("\n");
						continue;
					}

					rte_ether_addr_copy(&arp_h->arp_data.arp_sha,
										&eth_addr);
					ether_addr_dump("        sha=", &eth_addr);
					ip_addr = arp_h->arp_data.arp_sip;
					ipv4_addr_dump(" sip=", ip_addr);
					printf("\n");
					rte_ether_addr_copy(&arp_h->arp_data.arp_tha,
										&eth_addr);
					ether_addr_dump("        tha=", &eth_addr);
					ip_addr = arp_h->arp_data.arp_tip;
					ipv4_addr_dump(" tip=", ip_addr);
					printf("\n");

					if (arp_op != RTE_ARP_OP_REQUEST)
					{
						rte_pktmbuf_free(pkt);
						continue;
					}

					/*
					* Build ARP reply.
			 		*/

					printf("building arp reply\n");
					/* Use source MAC address as destination MAC address. */
					rte_ether_addr_copy(&eth_h->s_addr, &eth_h->d_addr);
					/* Set source MAC address with MAC address of TX port */
					struct rte_ether_addr addr;
					retval = rte_eth_macaddr_get(port, &addr);
					if (retval != 0)
					{
						printf("can't read mac address");
					}

					rte_ether_addr_copy(&addr, &eth_h->s_addr);

					arp_h->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
					rte_ether_addr_copy(&arp_h->arp_data.arp_tha,
										&eth_addr);
					rte_ether_addr_copy(&arp_h->arp_data.arp_sha,
										&arp_h->arp_data.arp_tha);
					rte_ether_addr_copy(&eth_h->s_addr,
										&arp_h->arp_data.arp_sha);


					/* Swap IP addresses in ARP payload */
					ip_addr = arp_h->arp_data.arp_sip;
					arp_h->arp_data.arp_sip = arp_h->arp_data.arp_tip;
					arp_h->arp_data.arp_tip = ip_addr;
					printf("  ARP:  hrd=%d proto=0x%04x hln=%d "
						   "pln=%d op=%u (%s)\n",
						   RTE_BE_TO_CPU_16(arp_h->arp_hardware),
						   arp_pro, arp_h->arp_hlen,
						   arp_h->arp_plen, arp_h->arp_opcode,
						   arp_op_name(arp_h->arp_opcode));
					pkts_burst[nb_replies++] = pkt;
				}

				/* Send burst of TX packets, to second port of pair. */
				const uint16_t nb_tx = rte_eth_tx_burst(port, 0,
														pkts_burst, nb_rx);

				/* Free any unsent packets. */
				if (unlikely(nb_tx < nb_rx))
				{
					uint16_t buf;
					for (buf = nb_tx; buf < nb_rx; buf++)
						rte_pktmbuf_free(pkts_burst[buf]);
				}
			}
		}
	}
}
/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports. */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the master core only. */
	lcore_main();

	return 0;
}
