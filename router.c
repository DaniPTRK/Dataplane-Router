#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

/* Structure for a node inside the trie. */
struct TrieNode {
	struct route_table_entry *rtable;
	struct TrieNode* next[2];
};

/* Queue structure */
struct package {
	struct route_table_entry *route;
	char buf[MAX_PACKET_LEN];
	size_t len;
};

/* Head of trie */
struct TrieNode *head;

/* Head of queue */
struct queue *queue_head;

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* ARP table */
struct arp_table_entry *arp_table;
int arp_table_len;

void create_trie_node(struct TrieNode** node) {
	/* Create node inside trie. */
	*node = (struct TrieNode*) malloc(sizeof(struct TrieNode));
	DIE(node == NULL, "memory");
	(*node)->rtable = NULL;
	(*node)->next[0] = NULL;
	(*node)->next[1] = NULL;
}

void insert_trie_node(struct route_table_entry* given_ip) {
	/* Insert node in trie. */
	struct TrieNode *p = head;
	uint32_t mask = 0, cont = 1 << 31;
	uint8_t bit;
	for(int i = 31; i >= 0; i--, cont = cont >> 1) {
		/* Get the bit and go through the trie.*/
		bit = (cont & ntohl(given_ip->prefix)) >> i;
		if(p->next[bit] == NULL) {
			create_trie_node(&(p->next[bit]));
		}
		p = p->next[bit];
		/* Update the mask with one bit.*/
		mask = mask | (1 << i);
		/* Check if mask is equal to the given mask. */
		if(mask == ntohl(given_ip->mask)) {
			if(p->rtable == NULL) {
				p->rtable = (struct route_table_entry*)malloc(sizeof(struct route_table_entry));
				DIE(p->rtable == NULL, "memory");
				memcpy(p->rtable, given_ip, sizeof(struct route_table_entry));
			}
			break;
		}
	}
}

struct route_table_entry *get_best_route(uint32_t ip_dest) {
	/* Get the best matching route. */
	struct route_table_entry* best_route = NULL;
	struct TrieNode *p = head;
	uint32_t cont = 1 << 31;
	uint8_t bit;
	for(int i = 31; i >= 0; i--, cont = cont >> 1) {
		/* Get the bit and go through the trie. */
		bit = (cont & ntohl(ip_dest)) >> i;
		p = p->next[bit];
		if(p != NULL) {
			if(p->rtable != NULL) {
				best_route = p->rtable;
			}
		} else {
			return best_route;
		}
	}
	return best_route;
}

struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
	for(int i = 0; i < arp_table_len; i++) {
		/* Search for an entry that matches up the given ip. */
		if(arp_table[i].ip == given_ip) {
			return &arp_table[i];
		}
	}
	return NULL;
}

void update_ether_header(struct ether_header** eth1, struct ether_header* eth2) {
	/* Swapping hosts for ethernet header. */
	memcpy(*eth1, eth2, sizeof(struct ether_header));
	memcpy((*eth1)->ether_dhost, eth2->ether_shost, sizeof(eth2->ether_dhost));
	memcpy((*eth1)->ether_shost, eth2->ether_dhost, sizeof(eth2->ether_dhost));
}

void ARP_message(struct route_table_entry *best_route, struct ether_header *eth_hdr) {
	/* Build the ARP request buffer. */
	char arp_buf[MAX_PACKET_LEN];

	/* Set up the new length. */
	size_t len = sizeof(struct ether_header) + sizeof(struct arp_header);

	struct ether_header *eth_hdr_arp = malloc(sizeof (struct ether_header));
	DIE(eth_hdr_arp == NULL, "memory");
	struct arp_header *arp_hdr = malloc(sizeof (struct arp_header));
	DIE(arp_hdr == NULL, "memory");

	/* Update ether header. */
	get_interface_mac(best_route->interface, eth_hdr_arp->ether_shost);
	eth_hdr_arp->ether_type = htons(0x0806);
	for(int i = 0; i < 6; i++) {
		eth_hdr_arp->ether_dhost[i] = 0xff;
	}


	/* Set arp header for request. */
	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(0x0800);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(1);
	get_interface_mac(best_route->interface, arp_hdr->sha);
	arp_hdr->spa = inet_addr(get_interface_ip(best_route->interface));
	arp_hdr->tpa = best_route->next_hop;

	/* Build and send the arp buffer. */
	memcpy(arp_buf, eth_hdr_arp, sizeof(struct ether_header));
	memcpy(arp_buf + sizeof(struct ether_header), arp_hdr, sizeof(struct arp_header));
	send_to_link(best_route->interface, arp_buf, len);
}

void ARP_reply(int interface, struct ether_header *eth_hdr, char* buf) {
	/* Build the reply buffer. */
	char rep_buf[MAX_PACKET_LEN];
	/* Set up the new length. */
	size_t len = sizeof(struct ether_header) + sizeof(struct arp_header);

	struct ether_header *eth_hdr_rep = (struct ether_header *) rep_buf;
	struct arp_header *arp_hdr_rep = (struct arp_header *) (rep_buf + sizeof(struct ether_header));
	struct arp_header *arp_hdr_aux = malloc(sizeof(struct arp_header));

	update_ether_header(&eth_hdr_rep, eth_hdr);

	/* Update arp header. */
	memcpy(arp_hdr_rep, buf + sizeof(struct ether_header), sizeof(struct arp_header));
	memcpy(arp_hdr_aux, arp_hdr_rep, sizeof(struct arp_header));
	arp_hdr_rep->op = htons(2);
	memcpy(&arp_hdr_rep->spa, &arp_hdr_aux->tpa, sizeof(uint32_t));
	memcpy(&arp_hdr_rep->tpa, &arp_hdr_aux->spa, sizeof(uint32_t));
	memcpy(arp_hdr_rep->tha, arp_hdr_rep->sha, sizeof(arp_hdr_rep->tha));
	get_interface_mac(interface, arp_hdr_rep->sha);

	/* Set the sending host. */
	get_interface_mac(interface, eth_hdr_rep->ether_shost);

	send_to_link(interface, rep_buf, len);
}

void ARP_solve(int interface, char *buf) {
	/* Solve ARP buffer. */
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
	struct ether_header *eth_hdr;
	struct queue *sec_queue = queue_create();
	struct package *curr_package;
	struct arp_table_entry *nexthop;
	/* Search for MAC inside the table */
	int index = -1;
	for(int i = 0; index == -1 && i < arp_table_len; i++) {
		if(memcmp(arp_table[i].mac, arp_hdr->sha, 6*sizeof(uint8_t)) == 0) {
			index = i;
		}
	}
	/* If MAC isnt inside table, insert it.*/
	if(index == -1) {
		arp_table[arp_table_len++].ip = arp_hdr->spa;
		memcpy(arp_table[arp_table_len - 1].mac, arp_hdr->sha, 6*sizeof(uint8_t));
		index = arp_table_len-1;
	}

	/* Search for package that has the nexthop. */
	while(!queue_empty(queue_head)) {
		curr_package = queue_deq(queue_head);
		nexthop = get_arp_entry(curr_package->route->next_hop);
		if(nexthop != NULL) {
			/* Found the package. Put every dequed element back inside the main queue.*/
			while(!queue_empty(sec_queue)) {
				queue_enq(queue_head, queue_deq(sec_queue));
			}
			/* Get the ethernet header from the waiting package and send it. */
			eth_hdr = (struct ether_header*) curr_package->buf;
			memcpy(eth_hdr->ether_dhost, nexthop->mac, sizeof(eth_hdr->ether_dhost));
			get_interface_mac(curr_package->route->interface, eth_hdr->ether_shost);
			send_to_link(curr_package->route->interface, curr_package->buf, curr_package->len);
			break;
		} else {
			queue_enq(sec_queue, curr_package);
		}
	}
	queue_head = sec_queue;
}

void ICMP_message(int interface, struct ether_header *eth_hdr, struct iphdr *ip_hdr, char *buf, int type) {
	/* Build the error buffer. */
	char err_buf[MAX_PACKET_LEN];

	/* Set up the new length.*/
	size_t len = sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 64;

	struct ether_header *eth_hdr_err = (struct ether_header *) err_buf;
	struct iphdr *ip_hdr_err = (struct iphdr *)(err_buf + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(err_buf + sizeof(struct ether_header) + sizeof(struct iphdr));

	memset(icmp_hdr, 0, sizeof(struct icmphdr));

	/* Update ether header. */
	update_ether_header(&eth_hdr_err, eth_hdr);

	/* First, build the IPv4 header.*/
	memcpy(ip_hdr_err, ip_hdr, sizeof(struct iphdr));
	ip_hdr_err->daddr = ip_hdr->saddr;
	ip_hdr_err->saddr = ip_hdr->daddr;

	/* Update length, TTL and protocol of header. */
	ip_hdr_err->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr_err->ttl = 64;
	ip_hdr_err->protocol = IPPROTO_ICMP;

	/* Update check. */
	ip_hdr_err->check = 0;
	ip_hdr_err->check = htons(checksum((uint16_t*) ip_hdr_err, sizeof(struct iphdr)));

	/* Afterwards, build the ICMP header. */
	icmp_hdr->type = type;

	/* Compute the checksum for ICMP. */
	icmp_hdr->checksum = htons(checksum((uint16_t*)icmp_hdr, sizeof(struct icmphdr)));

	memcpy(err_buf + len - sizeof(struct iphdr) - 64, buf + sizeof(struct ether_header), sizeof(struct iphdr) + 64);
	
	/* Send the error buffer. */
	send_to_link(interface, err_buf, len);
}

void ICMP_reply(int interface, struct ether_header *eth_hdr, struct iphdr *ip_hdr, char *buf, size_t len) {
	/* Echo reply packet. */
	struct ether_header *eth_hdr_rep = (struct ether_header*) buf;
	struct iphdr *ip_hdr_rep = (struct iphdr *)(buf + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr*)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	uint16_t old_check, old_ttl;

	/* Update ether header. */
	update_ether_header(&eth_hdr_rep, eth_hdr);

	/* Reverse addresses. */
	memcpy(ip_hdr_rep, ip_hdr, sizeof(struct iphdr));
	ip_hdr_rep->saddr = ip_hdr->daddr;
	ip_hdr_rep->daddr = ip_hdr->saddr;

	/* Modify TTL.*/
	old_ttl = ip_hdr_rep->ttl;
	ip_hdr_rep->ttl--;
	old_check = ip_hdr_rep->check;
	ip_hdr_rep->check = 0;
	ip_hdr_rep->check = ~(~old_check +  ~((uint16_t)old_ttl) + (uint16_t)ip_hdr->ttl) - 1;

	/* Build ICMP header for reply. */
	icmp_hdr->type = 0;
	icmp_hdr->code = 0;

	send_to_link(interface, buf, len);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	struct package *pack;

	// Do not modify this line
	init(argc - 2, argv + 2);

	/* Code to allocate the route tables */
	rtable = malloc(sizeof(struct route_table_entry) * 70000);
	DIE(rtable == NULL, "memory");
	rtable_len = read_rtable(argv[1], rtable);
	arp_table = malloc(sizeof(struct arp_table_entry) * 100);
	DIE(arp_table == NULL, "memory");
	arp_table_len = 0;
	
	create_trie_node(&head);
	queue_head = queue_create();

	/* Create trie */
	for(int i = 0; i < rtable_len; i++) {
		insert_trie_node(&rtable[i]);
	}

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		/* Check what kind of packet we received. */
		if (ntohs(eth_hdr->ether_type) == 0x0800) {
			/* Received IPv4 packet.*/
			printf("Received IPv4 packet\n");
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			/* Check the ip_hdr */
			uint16_t old_check = ip_hdr->check;
			ip_hdr->check = 0;
			if(old_check != htons(checksum((uint16_t*)ip_hdr, sizeof(struct iphdr)))) {
				memset(buf, 0, sizeof(buf));
				printf("Wrong checksum\n");
				continue;
			}

			if(inet_addr(get_interface_ip(interface)) == ip_hdr->daddr) {
				/* ICMP Echo reply.*/
				printf("ICMP echo reply\n");
				ICMP_reply(interface, eth_hdr, ip_hdr, buf, len);
				continue;
			}

			/* Check TTL.*/
			if(ip_hdr->ttl <= 1) {
				/* Send ICMP message.*/
				printf("Time exceeded\n");
				ICMP_message(interface, eth_hdr, ip_hdr, buf, 11);
				continue;
			}
			uint16_t old_ttl;
			old_ttl = ip_hdr->ttl;
			ip_hdr->ttl--;
			
			/* Get best route table entry. */
			struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
			if(best_route == NULL) {
				/* Send ICMP message. */
				printf("Destination unreachable\n");
				ICMP_message(interface, eth_hdr, ip_hdr, buf, 3);
				continue;
			}

			/* Updating checksum. */
			ip_hdr->check = ~(~old_check +  ~((uint16_t)old_ttl) + (uint16_t)ip_hdr->ttl) - 1;

			/* Get ARP entry. */
			struct arp_table_entry *nexthop = get_arp_entry(best_route->next_hop);

			if(nexthop == NULL) {
				printf("ARP address not found\n");
				pack = (struct package*)malloc(sizeof(struct package));
				DIE(pack == NULL, "memory");
				pack->route = (struct route_table_entry *) malloc(sizeof(struct route_table_entry));
				DIE(pack->route == NULL, "memory");
				memcpy(pack->route, best_route, sizeof(struct route_table_entry));
				memcpy(pack->buf, buf, len);
				pack->len = len;
				queue_enq(queue_head, (void *)pack);
				ARP_message(best_route, eth_hdr);
				continue;
			}
			memcpy(eth_hdr->ether_dhost, nexthop->mac, sizeof(eth_hdr->ether_dhost));
			get_interface_mac(best_route->interface, eth_hdr->ether_shost);
			send_to_link(best_route->interface, buf, len);
			continue;
		} else if(ntohs(eth_hdr->ether_type) == 0x0806) {
			/* Received ARP packet.*/
			printf("Received ARP\n");
			struct arp_header *arphdr = (struct arp_header*)(buf + sizeof(struct ether_header));
			if(ntohs(arphdr->op) == 1) {
				/* Replying to ARP packet */
				printf("Replying to ARP\n");
				ARP_reply(interface, eth_hdr, buf);
				continue;
			} else if(ntohs(arphdr->op) == 2) {
				/* Solving the reply packet */
				printf("Solving ARP\n");
				ARP_solve(interface, buf);
				continue;
			}
			continue;
		} else {
			/*Received a different packet. Ignore it.*/
			printf("Ignored packet\n");
			continue;
		}
	}
}