
#include "config.h"
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <map>
#include <deque>
#include <net/ethernet.h>
#include <cstring>
#include <string>
#include <pcap/pcap.h>
#include <sys/stat.h>
#include <sys/types.h>


#include <iostream>
using std::cerr;
using std::endl;
using std::hex;
using std::dec;

static const char *dev = "eth0";
static int promiscuous = 0;
static int count_packet = -1;
static const char *filter = NULL;
static const char *filename = NULL;
static int buffer_size = 8192;

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
	sock_s () {}
	sock_s (const addr_s &a, int p) :addr(a), port(p) {}
	bool operator <(const sock_s &s) const {
		if(addr<s.addr) return 1;
		else if(s.addr<addr) return 0;
		return port<s.port;
	}
};

template<typename container_t>
int parse_string(container_t c, std::string &s, int start, int end, int last=0)
{
	while(start<end && last?(c[start]!=last):isspace(c[start]))
		s.push_back(c[start++]);
	return start;
}

static FILE * myfopenw(const char *name)
{
	char *s = new char[strlen(name)+10];
	strcpy(s, name);
	cerr<<"info: myfopenw("<<name<<")"<<endl;
	char *p, *p1;
	for(p=s; *p && (p1=strchr(p, '/')); p=p1+1) {
		*p1 = 0;
		//cerr<<" mkdir("<<s<<")"<<endl;
		mkdir(s, 0755);
		*p1 = '/';
	}
	FILE *fp=NULL;
	for(int n=0; !fp && n<10; n++) {
		fp = fopen(s, "w");
		if(!fp) {
			sprintf(s, "%s-%d", name, n);
		}
	}
	if(!fp)
		perror("fopen");
	delete[] s;
	return fp;
}

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
		int seq_first, seq_offset, seq_ack;

		u_char operator [] (int s) const {
			int x = s-seq_offset;
			if(0<=x && x<data.size())
				return data[x];
			else
				return 0;
		}

		void syn(int seq) {
			state = state_est;
			seq_first = seq_offset = seq_ack = seq+1;
		}
		void update(int seq, int len, const u_char *dat) {
			int size_1 = seq-seq_offset + len;
			if(data.size()<size_1)
				data.resize(size_1);
			//else cerr<<"debug: data.size="<<data.size()<<" size_1="<<size_1<<endl;
			for(int i=0, j=seq-seq_offset; i<len; i++, j++)
				if(j>=0)
					data[j] = dat[i];
		}
		void ack(int seq) {
			if((seq-seq_ack)>0) {
				if(seq_ack-seq_offset > data.size()) {
					fprintf(stderr, "warning: packet dropped: data lost seq: %u to %u\n",
							seq_offset+data.size(), seq_ack );
				}
				seq_ack = seq;
			}
		}
		void fin() {
			state = state_fin;
		}
		void advance(int seq) {
			int size = seq - seq_offset;
			//cerr<<"  advance size="<<size<<endl;
			if(0<size && size<=data.size()) {
				seq_offset = seq;
				data.erase(data.begin(), data.begin()+size);
			}
			else if(data.size()<size) {
				cerr<<"debug: advance size="<<size<<" data-size="<<data.size()<<endl;
				seq_offset = seq;
				data.clear();
			}
		}
	};

	sequence_s up, down;
	std::pair<sock_s,sock_s> socks;

	enum http_state_e {
		http_init,
		http_11_get,
		http_10_data,
		http_11_data,
		http_parsed,
		http_unknown,
	} http_state;
	std::string url;
	std::string filename;
	long long content_length;
	bool keep_alive;
	bool chunked;
	FILE *fp;
	long long position;

	void init_http_state() {
		http_state = http_init;
		content_length = -1;
		keep_alive = 0;
		chunked = 0;
		position = 0;
		if(fp) fclose(fp); fp = NULL;
	}

	tcp_stream_s() {
		fp = NULL;
		init_http_state();
	}

	~tcp_stream_s() {
		if(fp) fclose(fp); fp=NULL;
	}

	void doit() {
		if(up.state==sequence_s::state_fin && down.state==sequence_s::state_fin && http_state!=http_parsed) {
			static int id = 0;
			char name[64];
			sprintf(name, "/tmp/http-%04d-up.dat", id);
			FILE *fp = fopen(name, "w");
			for(int i=0; i<up.data.size(); i++)
				fputc(up.data[i], fp);
			fclose(fp);
			sprintf(name, "/tmp/http-%04d-down.dat", id);
			fp = fopen(name, "w");
			for(int i=0; i<down.data.size(); i++)
				fputc(down.data[i], fp);
			fclose(fp);
			id++;
		}

		if(http_state==http_init) {
			parse_request();
		}
		if(http_state==http_11_get) {
			parse_11_response();
		}
		if(http_state==http_10_data || http_state==http_11_data) {
			parse_data();
		}
	}

	void parse_data() {
		if(!fp) {
			fp = myfopenw(filename.c_str());
		}

		if(content_length>=0) {
			int size = 0;
			int seq = down.seq_offset;
			cerr<<" content_length="<<content_length<<" seq="<<seq<<" ack="<<down.seq_ack<<endl;
			for(; content_length>position && (down.seq_ack-seq)>0; ) {
				if(fp) fputc(down[seq], fp);
				size++;
				position++;
				seq++;
			}
			if(size) {
				down.advance(seq);
			}
			if(content_length==position && down.seq_ack-seq>=2) {
				if(down[seq]=='\r' && down[seq+1]=='\n')
					down.advance(seq+=2);
				if(fp) fclose(fp); fp = NULL;
				http_state = http_parsed;
				cerr<<"debug: URL<"<<url<<"> data-parser end Content-Length="<<content_length<<endl;
			}
		}
		else if(chunked) {
			int seq = down.seq_offset;
			std::string s_size;
			seq = parse_string(down, s_size, seq, down.seq_ack, '\r');
			if(down[seq]=='\r' && down[seq+1]=='\n') {
				seq += 2;
				int size = strtol(s_size.c_str(), NULL, 16);
				if(size==0) {
					if(fp) fclose(fp); fp = NULL;
					http_state = http_parsed;
				}
				else if(down.seq_ack-seq >= size+2) {
					for(int i=0; i<size && seq!=down.seq_ack; i++) {
						if(fp) fputc(down[seq], fp);
						position++;
						seq++;
					}
					if(down[seq]=='\r' && down[seq+1]=='\n') {
						seq += 2;
					}
					down.advance(seq);
				}
			}
		}
		else {
			while(down.seq_offset!=down.seq_ack) {
				fputc(down[down.seq_offset], fp);
				down.advance(down.seq_offset+1);
				position++;
			}
		}

		if(http_state==http_parsed && keep_alive) {
			cerr<<"debug: port="<<socks.first.port<<" reset HTTP parser because of keep-alive"<<endl;
			init_http_state();
		}
	}

	void parse_11_response() {
		int end=down.seq_offset;
		for(int i=end, j=0; i!=down.seq_ack; i++) {
			const u_char term[]="\r\n\r\n";
			if(down[i]==term[j]) {
				j++;
				if(j==4) {
					end = i-3;
					cerr<<" end found: length="<<(end-down.seq_offset)<<endl;
					break;
				}
			}
			else
				j = 0;
		}
		cerr<<" parse_11_response: end:"<<end-down.seq_offset<<" ack="<<down.seq_ack-down.seq_offset<<endl;
		if(end != down.seq_offset) {
			std::string http_ver, s_code, status;
			int seq = down.seq_offset;
			seq = parse_string(down, http_ver, seq, down.seq_ack, ' ')+1;
			seq = parse_string(down, s_code  , seq, down.seq_ack, ' ')+1;
			seq = parse_string(down, status  , seq, down.seq_ack, '\r')+2;
			int code = atoi(s_code.c_str());
			cerr<<" ver=["<<http_ver<<"] code="<<code<<" data[0]="<<(char)down.data[0]<<endl;
			for(; (end-seq)>0 && down[seq]!='\r'; ) {
				std::string a, b;
				seq = parse_string(down, a, seq, down.seq_ack, ':')+2;
				seq = parse_string(down, b, seq, down.seq_ack, '\r')+2;
				if(a=="Content-Length")
					content_length = atoll(b.c_str());
				else if(a=="Connection" && b=="keep-alive")
					keep_alive = 1;
				else if(a=="Transfer-Encoding" && b=="chunked")
					chunked = 1;
			}
			if(http_ver=="HTTP/1.0") {
				if(code/100==2) {
					cerr<<"debug: port="<<socks.first.port<<" parser: HTTP/1.0 receiver"<<endl;
					http_state = http_10_data;
					down.advance(end+4);
				}
				else if(keep_alive)
					init_http_state();
			}
			else if(http_ver=="HTTP/1.1") {
				if(code/100==2) {
					cerr<<"debug: port="<<socks.first.port<<" parser: HTTP/1.1 receiver"<<endl;
					http_state = http_11_data;
					down.advance(end+4);
				}
				else if(keep_alive)
					init_http_state();
			}
			else {
				http_state = http_unknown;
			}
		}
	}

	void parse_request() {
		//while(up.data.size() && up[up.seq_offset]=='\r' && up[up.seq_offset+1]=='\n')
		//	up.advance(up.seq_offset+2);
		//while(up.data.size() && up[up.seq_offset]=='\n')
		//	up.advance(up.seq_offset+1);
		int end=up.seq_offset;
		for(int i=end, j=0; i!=up.seq_ack; i++) {
			const u_char term[]="\r\n\r\n";
			if(up[i]==term[j]) {
				j++;
				if(j==4) {
					end = i-3;
					break;
				}
			}
			else
				j = 0;
		}
		//cerr<<" parse_request: end:"<<end-up.seq_offset<<" ack="<<up.seq_ack-up.seq_offset<<endl;
		//if(up.seq_ack-end>=4) { cerr<<"  first:"; for(int i=up.seq_offset,j=0; j<4; i++, j++) cerr<<' '<<hex<<(int)up[i]; cerr<<dec<<endl; }
		//if(up.seq_ack-end>=4) { cerr<<"   last:"; for(int i=up.seq_ack-4; i!=up.seq_ack; i++) cerr<<' '<<hex<<(int)up[i]; cerr<<dec<<endl; }
		if(end != up.seq_offset) {
			std::string method, path, http_ver, host;
			int seq = up.seq_offset;
			seq = parse_string(up, method, seq, up.seq_ack, ' ')+1;
			seq = parse_string(up, path, seq, up.seq_ack, ' ')+1;
			seq = parse_string(up, http_ver, seq, up.seq_ack, '\r')+2;
			cerr<<" port="<<socks.first.port<<"  method=["<<method<<"] path=["<<path<<"]"<<endl;
			for(; (end-seq)>0 && up[seq]!='\r'; ) {
				std::string a, b;
				seq = parse_string(up, a, seq, up.seq_ack, ':')+2;
				seq = parse_string(up, b, seq, up.seq_ack, '\r')+2;
				//cerr<<" port="<<socks.first.port<<" a=["<<a<<"] b=["<<b<<"]"<<endl;
				if(a=="Host")
					host = b;
			}
			if(method=="GET" && http_ver=="HTTP/1.1") {
				static int id=0;
				char s[16]; sprintf(s, "%08d.dat", id++);
				http_state = http_11_get;
				up.advance(end+4);
				url = "http://" + host + path;
				filename = "http/" + host + "/" + s;
				cerr<<"url=["<<url<<"] filename="<<filename<<endl;
			}
			else
				http_state = http_unknown;
		}
	}
};

std::map<std::pair<sock_s,sock_s>, tcp_stream_s> tcp_streams;

static void do_tcp(const struct pcap_pkthdr *h, const addr_s &addr_from, const addr_s &addr_to, int length, const u_char *bytes)
{
	int port_from = (bytes[0]<<8) | bytes[1];
	int port_to = (bytes[2]<<8) | bytes[3];
	int sequence = (bytes[4]<<24) | (bytes[5]<<16) | (bytes[6]<<8) | bytes[7];
	int ackno = (bytes[8]<<24) | (bytes[9]<<16) | (bytes[10]<<8) | bytes[11];
	int length_header = (bytes[12]>>4)*4;
	int flags = bytes[13]&0x3F;
	/*
	printf(" TCP from=%d to=%d seq=%d len_h=%d flags=%x len_d=%d  ",
			port_from, port_to,
			sequence, length_header,
			flags,
			length-length_header );
	for(int i=length_header, j=0; i<length && j<64; i++, j++) putchar(isprint(bytes[i]) ?  bytes[i] : '.');
	puts("");
	*/

	sock_s sock_from(addr_from, port_from);
	sock_s sock_to  (addr_to  , port_to  );
	std::pair<sock_s,sock_s> pair_up(sock_from, sock_to);
	std::pair<sock_s,sock_s> pair_down(sock_to, sock_from);

	if(flags==0x02) {
		tcp_stream_s &tcp = tcp_streams[pair_up];
		tcp.socks = pair_up;
		tcp.up.syn(sequence);
	}
	else if(flags==0x12) {
		tcp_stream_s &tcp = tcp_streams[pair_down];
		tcp.down.syn(sequence);
	}
	else if(tcp_streams.count(pair_up)) {
		tcp_stream_s &tcp = tcp_streams[pair_up];
		tcp.up.update(sequence, length-length_header, bytes+length_header);
		if(flags & 0x10)
			tcp.down.ack(ackno);
		if(flags & 0x01)
			tcp.up.fin();
		tcp.doit();
	}
	else if(tcp_streams.count(pair_down)) {
		tcp_stream_s &tcp = tcp_streams[pair_down];
		tcp.down.update(sequence, length-length_header, bytes+length_header);
		if(flags & 0x10)
			tcp.up.ack(ackno);
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
			case 'B':
				if(i<argc) {
					buffer_size = atoi(argv[i++]);
				}
				else {
					fprintf(stderr, "error: option -%c requires extra arguments\n", c);
					return (int)c;
				}
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
			case 'r':
				if(i<argc)
					filename = argv[i++];
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

	pcap_t *cap;

	if(filename) {
		char errbuf[PCAP_ERRBUF_SIZE];
		memset(errbuf, 0, sizeof(errbuf));
		cap = pcap_open_offline(filename, errbuf);
		if(errbuf[0])
			fprintf(stderr, "%s\n", errbuf);
		if(!cap)
			return __LINE__;
	}
	else {
		char errbuf[PCAP_ERRBUF_SIZE];
		memset(errbuf, 0, sizeof(errbuf));
		cap = pcap_open_live(dev, buffer_size, promiscuous, 4000, errbuf);
		if(errbuf[0])
			fprintf(stderr, "%s\n", errbuf);
		if(!cap)
			return __LINE__;
	}

	if(filter) {
		struct bpf_program prog;
		if(pcap_compile(cap, &prog, filter, 1, PCAP_NETMASK_UNKNOWN)) {
			pcap_perror(cap, (char*)"pcap_compile");
			return __LINE__;
		}
		if(pcap_setfilter(cap, &prog)) {
			pcap_perror(cap, (char*)"pcap_setfilter");
			return __LINE__;
		}
	}
	pcap_loop(cap, count_packet, callback, NULL);

	pcap_close(cap);

	return 0;
}
