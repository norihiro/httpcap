
#include "config.h"
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <map>
#include <deque>
#include <net/ethernet.h>
#include <cstring>
#include <pcap/pcap.h>

static const char *dev = "eth0";
static int promiscuous = 0;
static int count_packet = -1;
static const char *filter = NULL;

#define LEN_ADDR 16

struct addr_s
{
	u_char address[16];
	int length;
	int type;
	void set_ipv4(const u_char *bytes) {
		type = 4; // IPv4
		length = 4;
		memcpy(address, bytes, 4);
	}

	bool operator <(const addr_s &a) const {
		if(type!=a.type) return type<a.type;
		if(length!=a.length) return length<a.length;
		for(int i=0; i<length; i++) {
			if(address[i]!=a.address[i]) return address[i]<a.address[i];
		}
		return 0;
	}
};

struct sock_s
{
	addr_s addr;
	int port;
	sock_s (const addr_s &a, int p) :addr(a), port(p) {}
	bool operator <(const sock_s &s) const {
		if(addr<s.addr) return 1;
		else if(s.addr<addr) return 0;
		return port<s.port;
	}
};

struct tcp_stream_s
{
	struct sequence_s
	{
		enum state_e {
			state_syn,
			state_est,
			state_fin
		} state;
		std::deque <u_char> data;
		int seq_first, seq_offset;

		void syn(int seq) {
			state = state_est;
			seq_first = seq_offset = seq+1;
		}
		void update(int seq, int len, const u_char *dat) {
			int size_1 = seq-seq_offset + len;
			data.resize(size_1);
			for(int i=0, j=seq-seq_offset; i<len; i++, j++)
				if(j>=0)
					data[j] = dat[i];
		}
		void fin() {
			state = state_fin;
		}
	};

	sequence_s up, down;

	void doit() {
		if(up.state==sequence_s::state_fin && down.state==sequence_s::state_fin) {
			static int id = 0;
			char name[64];
			sprintf(name, "/tmp/http%04d-up.dat", id);
			FILE *fp = fopen(name, "w");
			for(int i=0; i<up.data.size(); i++)
				fputc(up.data[i], fp);
			fclose(fp);
			sprintf(name, "/tmp/http%04d-down.dat", id);
			fp = fopen(name, "w");
			for(int i=0; i<down.data.size(); i++)
				fputc(down.data[i], fp);
			fclose(fp);
			id++;
		}
	}
};

std::map<std::pair<sock_s,sock_s>, tcp_stream_s> tcp_streams;

static void do_tcp(const struct pcap_pkthdr *h, const addr_s &addr_from, const addr_s &addr_to, int length, const u_char *bytes)
{
	int port_from = (bytes[0]<<8) | bytes[1];
	int port_to = (bytes[2]<<8) | bytes[3];
	int sequence = (bytes[4]<<24) | (bytes[5]<<16) | (bytes[6]<<8) | bytes[7];
	int length_header = (bytes[12]>>4)*4;
	int flags = bytes[13]&0x3F;
	printf(" TCP from=%d to=%d seq=%d len_h=%d flags=%x len_d=%d\n",
			port_from, port_to,
			sequence, length_header,
			flags,
			length-length_header );

	sock_s sock_from(addr_from, port_from);
	sock_s sock_to  (addr_to  , port_to  );
	std::pair<sock_s,sock_s> pair_up(sock_from, sock_to);
	std::pair<sock_s,sock_s> pair_down(sock_to, sock_from);

	if(flags==0x02) {
		tcp_stream_s &tcp = tcp_streams[pair_up];
		tcp.up.syn(sequence);
	}
	else if(flags==0x12) {
		tcp_stream_s &tcp = tcp_streams[pair_down];
		tcp.down.syn(sequence);
	}
	else if(tcp_streams.count(pair_up)) {
		tcp_stream_s &tcp = tcp_streams[pair_up];
		tcp.up.update(sequence, length-length_header, bytes+length_header);
		if(flags & 0x01)
			tcp.up.fin();
		tcp.doit();
	}
	else if(tcp_streams.count(pair_down)) {
		tcp_stream_s &tcp = tcp_streams[pair_down];
		tcp.down.update(sequence, length-length_header, bytes+length_header);
		if(flags & 0x01)
			tcp.down.fin();
		tcp.doit();
	}

}

static void do_ipv4(const struct pcap_pkthdr *h, int length, const u_char *bytes)
{
	const u_char *data = bytes + (bytes[0]&0x0F)*4;
	int length_data = length - (bytes[0]&0x0F)*4;

	if(bytes[9]==0x06) /* TCP */ {
		addr_s from; from.set_ipv4(bytes+12);
		addr_s to  ; to  .set_ipv4(bytes+16);
		do_tcp(h, from, to, length_data, data);
	}
}

static void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	const struct ether_header *eh = (const struct ether_header*)(const void*)bytes;
	const u_char *ip = bytes + ETHER_HDR_LEN;

	if(ip[0]==0x45) {
		do_ipv4(h, h->len - ETHER_HDR_LEN, ip);
	}
	else {
		printf("%d.%06d caplen=%d len=%d",
				h->ts.tv_sec,
				h->ts.tv_usec,
				h->caplen,
				h->len );
		for(int i=0; i<12 && i<h->caplen-ETHER_HDR_LEN; i++)
			printf(" %02x", ip[i]);
		printf("\n");
	}
}

main(int argc, char **argv)
{
	for(int i=1; i<argc; ) {
		char *ai = argv[i++];
		if(ai[0]=='-') while(char c=*++ai) switch(c) {
			case 'd':
				if(i<argc)
					dev = argv[i++];
				else {
					fprintf(stderr, "error: option -%c requires extra arguments\n", c);
					return (int)c;
				}
				break;
			case 'p':
				promiscuous = 1;
				break;
			case 'c':
				if(i<argc) {
					count_packet = atoi(argv[i++]);
					if(count_packet<=0)
						count_packet = -1;
				}
				else {
					fprintf(stderr, "error: option -%c requires extra arguments\n", c);
					return (int)c;
				}
				break;
			case 'f':
				if(i<argc)
					filter = argv[i++];
				else {
					fprintf(stderr, "error: option -%c requires extra arguments\n", c);
					return (int)c;
				}
				break;
			default:
				fprintf(stderr, "error: unknown option: -%c\n", c);
				return 1;
		}
		else {
			fprintf(stderr, "error: too many arguments: %s\n", ai);
			return 2;
		}
	}
	char errbuf[PCAP_ERRBUF_SIZE];

	memset(errbuf, 0, sizeof(errbuf));
	pcap_t *cap = pcap_open_live(dev, 32768, promiscuous, 4000, errbuf);
	if(errbuf[0])
		fprintf(stderr, "%s\n", errbuf);
	if(!cap)
		return __LINE__;

	if(filter) {
		struct bpf_program prog;
		if(pcap_compile(cap, &prog, filter, 1, PCAP_NETMASK_UNKNOWN)) {
			pcap_perror(cap, "pcap_compile");
			return __LINE__;
		}
		if(pcap_setfilter(cap, &prog)) {
			pcap_perror(cap, "pcap_setfilter");
			return __LINE__;
		}
	}
	pcap_loop(cap, count_packet, callback, NULL);

	pcap_close(cap);

	return 0;
}
