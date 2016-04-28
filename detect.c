#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

//gcc three.c -lpcap

void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void arpspoof_detection(const u_char* packet);
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);
void print_sender_mac(const u_char* packet);
void print_dest_mac(const u_char* packet);
void print_sender_ip(const u_char* packet);
void print_dest_ip(const u_char* packet);

/* 
	IP and TCP structs based off of http://yuba.stanford.edu/~casado/pcap/section4.html
*/
	/* IP header */
	struct my_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		struct in_addr ip_src,ip_dst; /* source and dest address */
	};
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* TCP header */
	typedef u_int tcp_seq;

	struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
};

int count = 0;

int main(int argc, char *argv[]) {

	char error_buffer[PCAP_ERRBUF_SIZE];

	if(argc != 2){
		printf("Error! Please pass the name of the pcap file as argument.\n");
		return 0;
	}

	pcap_t *handle = pcap_open_offline(argv[1], error_buffer);

	if(handle == NULL){
		printf("Couldn't open file %s: %s\n", argv[1], error_buffer);
		return 0;
	}

	pcap_loop(handle, 0, my_packet_handler, NULL);
	pcap_close(handle);
	return 0;
}

void my_packet_handler(u_char *args, const struct pcap_pkthdr* header, const u_char* packet) {

	struct ether_header *eth_header = (struct ether_header *) packet;
	count++;

	//printf("\nPacket Type: ");
	print_packet_info(packet, *header);













	if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {

		struct ether_header *eth_header = (struct ether_header *) packet;
		struct my_ip *ip = (struct my_ip*)(packet + 14);
		u_int size_ip = IP_HL(ip)*4;
		struct sniff_tcp *tcp = (struct sniff_tcp*)(packet + 14 + size_ip);
		u_int size_tcp = TH_OFF(tcp)*4;


		//const char *payload; /* Packet payload */



		//size_ip = IP_HL(ip)*4;
		if (size_ip < 20) {
			printf("   * Invalid IP header length: %u bytes\n", size_ip);
			return;
		}

		if (size_tcp < 20) {
			printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
			return;
		}
		//payload = (u_char *)(packet + 14 + size_ip + size_tcp);

		printf("source port: %d\n", ntohs(tcp->th_sport));
		printf("target port: %d\n", ntohs(tcp->th_dport));




	}
	else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
		//printf("ARP\n");
		arpspoof_detection( packet );
	}
	else  if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) {
		//printf("Reverse ARP\n");
	}

	else {
		printf("Packet Type Error!\n");
	}

}

void arpspoof_detection( const u_char* packet ) {
	struct ether_arp* arpheader = (struct ether_arp *)(packet +14);

	if(124 == arpheader->arp_sha[0] && (192 != arpheader->arp_spa[0] || 168 != arpheader->arp_spa[1] || 0 != arpheader->arp_spa[2] || 100 != arpheader->arp_spa[3])){
		printf("\n\tPotential Spoof Found!\n");
		printf("\tOffending MAC: ");
		int i = 0;
		for (i=0; i<6; i++) {
			printf("%02X", arpheader->arp_sha[i]);
			if(i!=5)
			printf(":");
		}
		printf("\n\tOffending packet number: %d\n", count);
	}
	if(216 == arpheader->arp_sha[0] && (192 != arpheader->arp_spa[0] || 168 != arpheader->arp_spa[1] || 0 != arpheader->arp_spa[2] || 103 != arpheader->arp_spa[3])){
		printf("\n\tPotential Spoof Found!\n");
		printf("\tOffending MAC: ");
		int i = 0;
		for (i=0; i<6; i++) {
			printf("%02X", arpheader->arp_sha[i]);
			if(i!=5)
			printf(":");
		}
		printf("\n\tOffending packet number: %d\n", count);
	}
	if(248 == arpheader->arp_sha[0] && (192 != arpheader->arp_spa[0] || 168 != arpheader->arp_spa[1] || 0 != arpheader->arp_spa[2] || 1 != arpheader->arp_spa[3])){
		printf("\n\tPotential Spoof Found!\n");
		printf("\tOffending MAC: ");
		int i = 0;
		for (i=0; i<6; i++) {
			printf("%02X", arpheader->arp_sha[i]);
			if(i!=5)
			printf(":");
		}
		printf("\n\tOffending packet number: %d\n", count);
	}
}

void portscan() {

}

void synflood_detection() {
}
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {

	printf("\n");
	printf("\tPacket Info:\n");
	printf("\tPacket Number: %d\n", count);
	printf("\t\tPacket capture length: \t%d\n", packet_header.caplen);
	printf("\t\tPacket total length: \t%d\n", packet_header.len);
	printf("\n");
	print_sender_mac(packet);
	print_dest_mac(packet);
	print_sender_ip(packet);
	print_dest_ip(packet);
}
void print_sender_mac(const u_char* packet) {
	struct ether_arp* arpheader = (struct ether_arp *)(packet +14);
	printf("\t\tSender MAC: ");
	int i = 0;
	for (i=0; i<6; i++) {
		printf("%02X", arpheader->arp_sha[i]);
		if(i < 5)
			printf(":");
	}
	printf("\n");
}
void print_dest_mac(const u_char* packet) {
	struct ether_arp* arpheader = (struct ether_arp *)(packet +14);
	printf("\t\tDestination MAC: ");
	int i = 0;
	for (i=0; i<6; i++) {
		printf("%02X", arpheader->arp_tha[i]);
		if(i < 5)
			printf(":");
	}
	printf("\n");
}
void print_sender_ip(const u_char* packet) {
	struct ether_arp* arpheader = (struct ether_arp *)(packet +14);
	printf("\t\tSender IP: ");
	int i = 0;
	for (i=0; i<4; i++) {
		printf("%d",arpheader->arp_spa[i]);
		if(i < 3)
			printf(".");
	}
	printf("\n");
}
void print_dest_ip(const u_char* packet) {
	struct ether_arp* arpheader = (struct ether_arp *)(packet +14);
	printf("\t\tDestination IP: ");
	int i = 0;
	for (i = 0; i < 4; i++) {
		printf("%d", arpheader->arp_tpa[i]);
		if(i < 3)
			printf(".");
	}
	printf("\n");
}