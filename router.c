// Maria Moșneag 323CA

#include <queue.h>
#include "skel.h"

#define RT_ENTRIES 64270
#define ARP_ENTRIES 50

// structura de bază a tabelei de rutare
struct rt_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} __attribute__((packed));

// structura de bază a tabelei de ARP
struct arp_entry {
	uint32_t ip;
	u_char mac[6];
} __attribute__((packed));

// tabela de rutare
struct rt_entry *rtable;
int rt_size;

// tabela de ARP
struct arp_entry *arp_table;

// funcția de parsare a tabelei de rutare
static int read_rtable(char *in_file) {
	rtable = (struct rt_entry*) malloc(sizeof(struct rt_entry) * RT_ENTRIES);
	DIE(rtable == NULL, "memory");
	FILE *in = fopen(in_file, "r");
	char line[100];
	int i = 0;
	while (fgets(line, sizeof(line), in)) {
		char *token;
		token = strtok(line, " ");
		rtable[i].prefix = inet_addr(token);

		token = strtok(NULL, " ");
		rtable[i].next_hop = inet_addr(token);

		token = strtok(NULL, " ");
		rtable[i].mask = inet_addr(token);

		token = strtok(NULL, " ");
		rtable[i].interface = atoi(token);

		i++;
	}
	fclose(in);

	return i;
}

// funcție auxiliară pentru get_best_route
struct rt_entry *get_best_route_hlp(__u32 dest_ip, int l, int r) {
	if (r >= l) {
		int mid = l + (r - l) / 2;
		if ((dest_ip & rtable[mid].mask) ==
			(rtable[mid].prefix & rtable[mid].mask)) {
			return &rtable[mid];
		}
		if ((dest_ip & rtable[mid].mask) <
			(rtable[mid].prefix & rtable[mid].mask)) {
			return get_best_route_hlp(dest_ip, l, mid - 1);
		}
		return get_best_route_hlp(dest_ip, mid + 1, r);
	}

	return NULL;
}

// funcție ce returnează o intrare din tabela de rutare
// corespunzătoare adresei IP primite ca parametru
struct rt_entry *get_best_route(__u32 dest_ip) {
	return get_best_route_hlp(dest_ip, 0, rt_size - 1);
}

// funcție auxiliară pentru quickSort
int partition(int l, int r) {
	int p = rtable[r].prefix;
	int i = l - 1;
	struct rt_entry tmp;

	for (int j = l; j <= r - 1; j++) {
		if (rtable[j].prefix < p) {
			i++;
			memcpy(&tmp, &rtable[i], sizeof(struct rt_entry));
			memcpy(&rtable[i], &rtable[j], sizeof(struct rt_entry));
			memcpy(&rtable[j], &tmp, sizeof(struct rt_entry));
		}
	}
	memcpy(&tmp, &rtable[i + 1], sizeof(struct rt_entry));
	memcpy(&rtable[i + 1], &rtable[r], sizeof(struct rt_entry));
	memcpy(&rtable[r], &tmp, sizeof(struct rt_entry));

	return i + 1;
}

// funcție utilizată pentru sortarea tabelei de rutare
void quickSort(int l, int r) {
	if (l < r) {
		int p = partition(l, r);
		quickSort(l, p - 1);
		quickSort(p + 1, r);
	}
}

// funcția întoare intrarea din tabela de ARP corespunzătoare adresei IP primite ca parametru
struct arp_entry* get_next_arp(uint32_t ip, int arp_sz) {
	for (int i = 0; i < arp_sz; i++) {
		if (arp_table[i].ip == ip && arp_table[i].mac[0]) {
			return &arp_table[i];
		}
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	packet m;
	int rc;

	init(argc - 2, argv + 2);

	// construirea tabelei de rutare
	rt_size = read_rtable(argv[1]);
	quickSort(0, rt_size - 1);

	// alocarea tabelei de ARP
	arp_table = (struct arp_entry*) malloc(sizeof(struct arp_entry) * ARP_ENTRIES);
	DIE(arp_table == NULL, "memory");
	int crt_arp_free = 0;

	// inițializarea cozilor utilizate
	queue q, aux;
	q = queue_create();
	aux = queue_create();

	while (1) {
		struct rt_entry *go;
		struct arp_header *arp_hdr;

		// primirea unui pachet
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		struct ether_header *eth_hdr = (struct ether_header*) m.payload;
		struct iphdr *ip_hdr = (struct iphdr*) (m.payload + sizeof(struct ether_header));

		// verificarea tipului pachetului
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			// verific dacă este un pachet destinat router-ului meu
			struct in_addr ip_addr;
			inet_aton(get_interface_ip(m.interface), &ip_addr);
			if (ip_addr.s_addr == ip_hdr->daddr) {
				// verific dacă este un pachet icmp echo request
				struct icmphdr *icmp_hdr = parse_icmp(m.payload);
				if (icmp_hdr && icmp_hdr->type == ICMP_ECHO) {
					// trimit înapoi un răspuns
					send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost,
						eth_hdr->ether_shost, ICMP_ECHOREPLY, 0, m.interface, 0, 0);
				}
				continue;
			}

		} else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			arp_hdr = parse_arp(m.payload);
			if (arp_hdr == NULL) {
				continue;
			}

			// dacă pachetul este de tip ARP request, răspund cu un ARP reply
			if (ntohs(arp_hdr->op) == ARPOP_REQUEST) {
				struct in_addr ip_addr;
				inet_aton(get_interface_ip(m.interface), &ip_addr);

				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
				get_interface_mac(m.interface, eth_hdr->ether_shost);

				send_arp(arp_hdr->spa, arp_hdr->tpa, eth_hdr, m.interface,
						htons(ARPOP_REPLY));

			// dacă pachetul este de tip ARP reply, actualizez tabela de ARP
			// și trimit mai departe o parte dintre pachetele din coada de așteptare
			} else if (ntohs(arp_hdr->op) == ARPOP_REPLY) {
				int ok = 1;
				for (int i = 0; i < crt_arp_free && ok; i++) {
					if (arp_table[i].ip == arp_hdr->spa && arp_table[i].mac[0] == 0) {
						memcpy(arp_table[i].mac, arp_hdr->sha, 6);
						ok = 0;
					}
				}

				if (ok) {
					arp_table[crt_arp_free].ip = arp_hdr->spa;
					memcpy(arp_table[crt_arp_free].mac, arp_hdr->sha, 6);
					crt_arp_free++;
				} else {
					while (!queue_empty(q)) {
						packet *p = queue_deq(q);
						struct ether_header *eth_hdr = (struct ether_header*) p->payload;
						struct iphdr *ip_hdr2 = (struct iphdr*) (p->payload +
							sizeof(struct ether_header));

						go = get_best_route(ip_hdr2->daddr);
						struct arp_entry *next = get_next_arp(go->next_hop, crt_arp_free);
						if (next != NULL) {
							memcpy(eth_hdr->ether_dhost, next->mac, 6);
							get_interface_mac(go->interface, eth_hdr->ether_shost);
							send_packet(go->interface, p);
						} else {
							queue_enq(aux, p);
						}
					}
					while (!queue_empty(aux)) {
						queue_enq(q, queue_deq(aux));
					}
				}
			}
			continue;
		}

		// verific dacă ttl-ul pachetului este încă valid
		if (ip_hdr->ttl <= 1) {
			// în caz contrar trimit un mesaj de eroare
			struct in_addr ip_addr;
			inet_aton(get_interface_ip(m.interface), &ip_addr);

			uint8_t my_mac;
			get_interface_mac(m.interface, &my_mac);

			uint8_t d_mac;
			hwaddr_aton((char *)eth_hdr->ether_shost, &d_mac);
			send_icmp_error(ip_hdr->saddr, ip_addr.s_addr, &my_mac, &d_mac,
				ICMP_TIMXCEED, 0, m.interface);
			continue;
		}

		// verific checksum-ul pachetului
		if (ip_checksum(ip_hdr, sizeof(struct iphdr)) != 0) {
			continue;
		}

		// actualizez ttl-ul și checksum-ul
		uint16_t fst = *(uint16_t *)(ip_hdr + 64);
		ip_hdr->ttl--;
		uint16_t snd = *(uint16_t *)(ip_hdr + 64);
		ip_hdr->check = ~(~ip_hdr->check + ~fst + snd);

		// găsesc intrarea potrivită din tabela de rutare
		go = get_best_route(ip_hdr->daddr);
		if (go == NULL) {
			// în caz contrar trimit un mesaj de eroare
			struct in_addr ip_addr;
			inet_aton(get_interface_ip(m.interface), &ip_addr);

			uint8_t d_mac;
			hwaddr_aton((char *)eth_hdr->ether_dhost, &d_mac);

			uint8_t s_mac;
			hwaddr_aton((char *)eth_hdr->ether_shost, &s_mac);

			send_icmp_error(ip_hdr->saddr, ip_addr.s_addr, &d_mac, &s_mac,
				ICMP_DEST_UNREACH, 0, m.interface);
			continue;
		}

		// găsesc intrarea potrivită din tabela de ARP
		struct arp_entry *next = get_next_arp(go->next_hop, crt_arp_free);
		if (next == NULL) {
			// dacă nu am găsit un ARP entry, înseamnă că trebuie să trimitem
			// un ARP request și să punem pachetul actual în coada de așteptare
			packet *later = malloc(sizeof(packet));
			memcpy(later, &m, sizeof(packet));
			queue_enq(q, later);

			struct in_addr ip_addr;
			inet_aton(get_interface_ip(go->interface), &ip_addr);

			arp_table[crt_arp_free].ip = go->next_hop;

			memset(arp_table[crt_arp_free].mac, 0, 6);
			crt_arp_free++;

			struct ether_header *new_eth_hdr =
				(struct ether_header *)malloc(sizeof(struct ether_header));

			get_interface_mac(go->interface, new_eth_hdr->ether_shost);

			uint8_t dest[6];
			hwaddr_aton("ff:ff:ff:ff:ff:ff", dest);
			memcpy(new_eth_hdr->ether_dhost, dest, 6);
	
			new_eth_hdr->ether_type = htons(ETHERTYPE_ARP);

			send_arp(go->next_hop, ip_addr.s_addr, new_eth_hdr, go->interface,
				htons(ARPOP_REQUEST));

			continue;
		}

		// daca am găsit toate datele necesare, completăm adresele MAC sursă și destinație
		memcpy(eth_hdr->ether_dhost, next->mac, 6);
		get_interface_mac(go->interface, eth_hdr->ether_shost);

		// trimitem mai departe pachetul
		send_packet(go->interface, &m);
	}

	return 0;
}
