#include "Parse_packet.h"

using namespace std;

ParsePacket::ParsePacket() {
};

SplitPacket ParsePacket::Parse(const struct pcap_pkthdr *head, const u_char *packet) {
	SplitPacket s_pack;
	s_pack.header = *head;
	s_pack.ethernet = *(sniff_ethernet*)packet;
	s_pack.ip = *(sniff_ip *)(packet + SIZE_ETHERNET);
	s_pack.size_ip = (((s_pack.ip).ip_vhl) & 0x0f)*4;
	if (s_pack.size_ip < 20) {
        s_pack.flag = false;
		return s_pack;
	}
	switch(s_pack.ip.ip_p) {
		case IPPROTO_TCP:
			s_pack.flag = true;
			s_pack.tcp = *(struct sniff_tcp*)(packet + SIZE_ETHERNET + s_pack.size_ip);
			s_pack.size_tcp = (((s_pack.tcp).th_offx2 & 0xf0) >> 4) * 4;

			if (s_pack.size_tcp < 20) {
                s_pack.flag = false;
				return s_pack;
			}
			s_pack.size_payload = ntohs(s_pack.ip.ip_len) - (s_pack.size_ip + s_pack.size_tcp);
			s_pack.payload = new u_char[s_pack.size_payload];
			memmove(s_pack.payload, ( (u_char *)(packet + SIZE_ETHERNET + s_pack.size_ip + s_pack.size_tcp) ), s_pack.size_payload);
			break;
		case IPPROTO_UDP:
			s_pack.flag = true;
			s_pack.udp = *(struct sniff_udp*)(packet + SIZE_ETHERNET + s_pack.size_ip); //как-то нужно ведь смотреть длину заголовка
			s_pack.size_udp = UDP_LENGTH;

			if (s_pack.size_udp < 8) {
                s_pack.flag = false;
				return s_pack;
			}
            s_pack.size_payload = ntohs(s_pack.ip.ip_len) - (s_pack.size_ip + s_pack.size_udp);
            s_pack.payload = new u_char[s_pack.size_payload];
			memmove(s_pack.payload,(u_char *)(packet + SIZE_ETHERNET + s_pack.size_ip + s_pack.size_udp), s_pack.size_payload);
			break;
		default:
			s_pack.flag = false;
			return s_pack;
	}
	return s_pack;
};
