#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

char blockedhost[100];

struct ipv4_hdr
{
  u_int8_t IPverIHL;
  u_int8_t TOS;
  u_int16_t IPLen;
  u_int16_t PacketID;
  u_int16_t IPFlag;
  u_int8_t TTL;
  u_int8_t ProtocolType;
  u_int16_t IPHeaderChecksum;
  u_int8_t SIP[4];
  u_int8_t DIP[4];
};

struct tcp_hdr
{
  u_int16_t Sport;
  u_int16_t Dport;
  u_int8_t SeqNum[4];
  u_int8_t AckNum[4];
  u_int8_t THLReserved;
  u_int8_t Flag;
  u_int16_t WindowSize;
  u_int16_t CheckSum;
  u_int16_t UrgPt;
};

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d ", ret);

	fputc('\n', stdout);

	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	unsigned char *packet;
	u_int32_t ret=nfq_get_payload(nfa, &packet);
	char str[6][7]={"GET","POST","HEAD","PUT","DELETE","OPTIONS"};
	char str_size[6]={3,4,4,3,6,7};

	if(ret<0) 
	  return nfq_set_verdict(qh,id,NF_ACCEPT,0,NULL);

	if (ret>=0)
	{
	  struct ipv4_hdr *ip=(struct ipv4_hdr *)packet;
	  u_int8_t ip_hdr_len=((ip->IPverIHL)&0X0f)*4;

		if(ip->ProtocolType==IPPROTO_TCP)
		{
		  struct tcp_hdr *tcp=(struct tcp_hdr *)(packet+ip_hdr_len);
		  u_int16_t tcp_hdr_len=((tcp->THLReserved)>>4)*4;	
		  u_int16_t tcp_len=ntohs(ip->IPLen)-ip_hdr_len;
		  u_int16_t tcp_payload_len=tcp_len-tcp_hdr_len;
		  u_int8_t *tcp_payload=(u_int8_t *)(packet+ip_hdr_len+tcp_hdr_len);

		if(memcmp(tcp_payload,*str,str_size[0])==0||memcmp(tcp_payload,*(str+1),str_size[1])==0||memcmp(tcp_payload,*(str+2),str_size[2])==0||memcmp(tcp_payload,*(str+3),str_size[3])==0||memcmp(tcp_payload,*(str+4),str_size[4])==0||memcmp(tcp_payload,*(str+5),str_size[5])==0)
		{
			char *host;
			char *tmp=strstr(tcp_payload,"Host: ");

			tmp+=6;
			host=strtok(tmp, "\r");
			if(strncmp(blockedhost, host, strlen(blockedhost))!=0)
			  return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
  
			printf("%s Blocking\n",blockedhost);
			return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		}
	}
}
	printf("entering callback\n");
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void usage()
{
    puts("./netfilter_block <host_name>");
}

int main(int argc, char **argv)
{
	if(argc != 2){
		usage();
		return -1;
	}
	strcpy(blockedhost, argv[1]);

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
