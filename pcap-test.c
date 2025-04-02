// 2023350213 Jungwoo Park 

#include <pcap.h>             // pcap.h - pcap_open_live(), pcap_next_ex(), pcap_close() 등
#include <arpa/inet.h>        // arpa/inet.h - ntohl() 등  
#include <netinet/in.h>       // netinet/in.h - struct in_addr 등 

#include <stdio.h>
#include <stdbool.h> 
#include <stdint.h>

// 최대 출력 Payload
#define MAX_PRINT_LEN 20

// Ethernet II header
struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[6]; /* destination ethernet address */
    u_int8_t  ether_shost[6]; /* source ethernet address */
    u_int16_t ether_type;     /* protocol */
};

// IPv4 header - Little Endian 기준 
struct libnet_ipv4_hdr
{
    u_int8_t ip_hl:4,        /* header length */
             ip_v:4;         /* version */
    u_int8_t  ip_tos;        /* type of service */
    u_int16_t ip_len;        /* total length */
    u_int16_t ip_id;         /* identification */
    u_int16_t ip_off;        
    u_int8_t  ip_ttl;        /* time to live */
    u_int8_t  ip_p;          /* protocol */
    u_int16_t ip_sum;        /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

// TCP header - Little Endian 기준 
struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;         /* sequence number */
    u_int32_t th_ack;         /* acknowledgement number */
    u_int8_t th_x2:4,         /* (unused) */
             th_off:4;        /* data offset */
    u_int8_t  th_flags;       /* control flags */
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};


// usage() 함수 - 실행 시 인자를 제공 안할 경우, 올바른 사용법을 콘솔에 출력.
void usage() { 
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
	//printf("sample: pcap-test eth0\n");
} 

// Param 구조체 - 프로그램 실행 시 입력 받은 Network Interface 이름을 저장함. 
typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

// parse() 함수 - 프로그램 실행 시 전달된 인자 개수를 검증 및 param 구조체에 interface 이름 할당. 
bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

// print_mac 함수 - MAC 주소(6byte)를 "xx:xx:xx:xx:xx:xx"꼴로 출력.
void print_mac(const uint8_t* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// print_ipv4 함수 - ipv4 주소(4byte - in_addr 구조체체)를 "%u.%u.%u.%u"꼴로 출력.
void print_ipv4(struct in_addr addr) {
    unsigned const char *bytes = (unsigned const char *)&(addr.s_addr);
    printf("%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
}

// packet_interpret() 함수 - TCP 패킷인 경우에만 Ethernet header, IP header, TCP header, Payload(최대 MAX_PRINT_LEN 바이트)를 Display
void packet_interpret(const u_char* packet, const struct pcap_pkthdr* header)
{
    // [Check] TCP Packet Size Check (기본 헤더 사이즈)
    if (header->caplen < sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr)) // 패킷이 TCP 최소 크기를 만족하지 못함
        return; 

    // (1) Parsing - Ethernet Header 파싱 
    struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*) packet;

    // [Check] Ethernet Type이 IPv4(0x800)인지 확인 
    if (ntohs(eth_hdr->ether_type) != 0x0800) 
        return;

    // (2) Parsing - IPv4 Header 파싱 
    const u_char* ip_packet = packet + sizeof(struct libnet_ethernet_hdr);
    struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*) ip_packet;
    int ip_hdr_len = ip_hdr->ip_hl * 4; // IP 헤더 길이 (ip_hl가 4byte 단위임.)

    // [Check] 최소 IP 헤더 길이: ip_hl가 최소 5(20바이트)여야 함.
    if ((ip_hdr->ip_hl & 0x0F) < 5)
        return;

    // [Check] 캡처된 길이가 Ethernet + IP 헤더 길이보다 작은지 확인
    if (header->caplen < sizeof(struct libnet_ethernet_hdr) + ip_hdr_len)
        return;

    // [Check] Check if TCP(6) - 참고로, IPPROTO_TCP가 6임!
    if (ip_hdr->ip_p != IPPROTO_TCP) 
        return;

    // (3) Parsing - TCP Header 파싱 
    const u_char* tcp_packet = ip_packet + ip_hdr_len;
    struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*) tcp_packet;
    int tcp_hdr_len = tcp_hdr->th_off * 4; // TCP 헤더 길이 (tcp_off가 4byte 단위임.)

    // 전체 헤더 길이 계산 (Ethernet + IP + TCP)
    int total_header_len = sizeof(struct libnet_ethernet_hdr) + ip_hdr_len + tcp_hdr_len;

    // [Check] 캡처된 패킷 길이가 전체 헤더 길이보다 작은지 확인 (truncated packet)
    if (header->caplen < total_header_len) {
        printf("Truncated packet detected: caplen = %d, expected header length = %d\n\n", header->caplen, total_header_len);
        return;
    }

    // IP 헤더의 ip_len을 이용하여 실제 전송된 전체 IP 패킷 길이 계산 (헤더 + payload)
    int total_ip_len = ntohs(ip_hdr->ip_len);

    // [Check] 잘린 패킷의 경우, 실제 IP 길이가 캡처된 길이보다 클 수 있음.
    if (total_ip_len > (header->caplen - sizeof(struct libnet_ethernet_hdr))) {
        printf("Truncated IP packet: IP total length = %d, captured IP length = %d\n\n",
                total_ip_len, header->caplen - (int)sizeof(struct libnet_ethernet_hdr));
        return;
    }

    // Payload 추출 과정 및 잘린 패킷에 대한 예외 처리 
    const u_char* data = tcp_packet + tcp_hdr_len;
    int data_len = ntohs(ip_hdr->ip_len) - ip_hdr_len - tcp_hdr_len;
    // int data_len = header->caplen - total_header_len; // 잘못된 계산 방식임

    // 캡쳐된 TCP 패킷 정보 출력 
    printf("===== TCP Packet Captured =====\n");

        // (1) Ethernet Header 
    printf("Ethernet Header:\n");
    printf("  Src MAC: ");
    print_mac(eth_hdr->ether_shost);
    printf("\n");
    printf("  Dst MAC: ");
    print_mac(eth_hdr->ether_dhost);
    printf("\n");

        // (2) IPv4 Header
    printf("IP Header:\n");
    printf("  Src IP: ");
    print_ipv4(ip_hdr->ip_src);
    printf("\n");
    printf("  Dst IP: ");
    print_ipv4(ip_hdr->ip_dst);
    printf("\n");

        // (3) TCP Header
    printf("TCP Header:\n");
    printf("  Src Port: %u\n", ntohs(tcp_hdr->th_sport));
    printf("  Dst Port: %u\n", ntohs(tcp_hdr->th_dport));

        // (4) Payload(Data)
    printf("Payload (up to %d bytes):\n", MAX_PRINT_LEN);
    int print_len = (data_len > MAX_PRINT_LEN) ? MAX_PRINT_LEN : data_len;
    if (print_len <= 0) {
        printf("  -\n");
    } else {
        printf("  ");
        for (int i = 0; i < print_len; i++) {
            if (i > 0)
                printf("|");
            printf("%02x", data[i]);
        }
        printf("\n\n");
    }
}

int main(int argc, char* argv[]) {

    // parse() 함수로 올바른 인자가 전달되었는지 확인 후 interface 이름 받아옴.
	if (!parse(&param, argc, argv))
		return -1;

    // pcap_open_live() 함수로로 Packet Capture을 위한 준비 
        // char *device : param.dev_ - 네트워크 인터페이스 이름
        // int snaplen  : BUFSIZE    - 버퍼 크기, 패킷을 저장할 최대 바이트 수 (stdio.h 정의된 BUFSIZ) 
        // int promisc  : 1          - Promiscuous Mode (1: set) 즉, 자신에게 전달되지 않는 패킷도 모두 수신함.
        // int to_ms    : 1000       - Time Out 시간 (ms 단위이므로, 1000ms = 1s임.) 패킷을 기다릴 떄 최대 지연 시간임.
        // char *ebuf   : errbuf     - 에러 메시지를 저장할 버퍼 
	    // 열기 실패 시, 에러 출력 후 종료 (pcap 핸들을 받아옴.)
    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) { 
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1; 
	}

    // pcap_next_ex() 함수로로 각 iteration마다 패킷 캡쳐하기 
        // pcap_t *p                       : pcap    - pcap_open_live()로 생성된 캡쳐 세션의 핸들
        // struct pcap_pkthdr **pkt_header : &header - 캡처된 패킷 헤더 정보 반환 받을 포인터
        // const u_char **pkt_data         : &packet - 캡처된 패킷 데이터 반환 받을 포인터
        // 0(타임아웃 발생 - 일정 시간 대기했으나 패킷 없음) 반환 시, 다음 iteration으로 흐름.
        // PCAP_ERROR, PCAP_ERROR_BREAK 반환 시, 오류 발생 및 캡쳐 중단을 의미하므로 루프 빠져나가 종료. 
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
        packet_interpret(packet, header);
		//printf("%u bytes captured\n", header->caplen);
	}

    // pcap_close() 함수로 리소스 해제 
    // 즉, pcap_open_live()을 통해 생성된 세션 모두 종료
	pcap_close(pcap);
    return 0; 
}

