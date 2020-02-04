#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <netinet/ip.h> 
#include <netinet/ip_icmp.h>
#include <netdb.h> // for struct addrinfo and the function getaddrinfo()
#include <string.h> 
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <errno.h>

#define BUFSIZE 1500

void proc_v4(char *, ssize_t, struct timeval *);
void send_v4(void);

pid_t pid;
int nsent;
int datalen = 56;
int sockfd;
char recvbuf[BUFSIZE];
char sendbuf[BUFSIZE];

char *host;

struct addrinfo* host_serv(const char *host, const char *serv, int family, int socktype)
{
	int n;
	struct addrinfo hints, *res;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_CANONNAME; 
	hints.ai_family = family; 
	hints.ai_socktype = socktype; 

	if ( (n = getaddrinfo(host, serv, &hints, &res)) != 0)
		return (NULL);

	return (res); /* return pointer to first on linked list*/
}




char * sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
	static char str[128];		

	switch (sa->sa_family) {
	case AF_INET: 
	{
		struct sockaddr_in *sin = (struct sockaddr_in *) sa;

		if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
			return(NULL);
		return(str);
	}
	default:
		return(NULL);
	}
    return (NULL);
}

struct proto
{
	void (*fproc) (char *, ssize_t, struct timeval *);
	void (*fsend) (void);									////pointer to a function
	struct sockaddr *sasend; // sockaddr{} for send, from getaddrinfo
	struct sockaddr *sarecv; // sockaddr{} for receiving;
	socklen_t salen;
	int icmpproto;
} *pr;										////pointer to a structure

struct proto proto_v4 = {proc_v4, send_v4, NULL, NULL, 0, IPPROTO_ICMP};

void tv_sub(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0) 
	{
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	
	out->tv_sec -= in->tv_sec;
}

unsigned short in_cksum(unsigned short *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short	*w = addr;
	unsigned short	answer = 0;

	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(unsigned char *)(&answer) = *(unsigned char *)w ;
		sum += answer;
	}

		/* 4add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return(answer);
}

void proc_v4(char *ptr, ssize_t len, struct timeval *tvrecv)
{
	int hlen1, icmplen;
	double rtt;
	struct ip *ip;            ////is a pointer to structure ip
	struct icmp *icmp;			/////is a pointer to structure ICMP 
	struct timeval *tvsend;

	ip = (struct ip *) ptr; /* start of IP header */
	hlen1 = ip->ip_hl << 2; /* length of IP header */  
	//printf("%d", hlen1);

	icmp = (struct icmp *)(ptr + hlen1); /* start of ICMP header */

	if ( (icmplen = len - hlen1) < 8)				////ICMP header length has to be 8bytes
	{
		printf("icmplen (%d) < 8", icmplen);		////if ICMP header length is less than 8bytes then something is wrong
		exit(0);
	}

	if (icmp->icmp_type == ICMP_ECHOREPLY) 			////if this reply is ICMP echo reply then only we will reply
	{
		if (icmp->icmp_id != pid)					////process id must match
			return; /* not a response to our ECHO REQUEST */
		if (icmplen < 16)							////8bytes is for timestamp field therefore matching it with it
		{
			printf("icmplen (%d) < 16", icmplen);
			exit(0);
		}

		tvsend = (struct timeval *) icmp->icmp_data;
		tv_sub(tvrecv, tvsend);
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec/1000.0;

		printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n", icmplen, sock_ntop_host(pr->sarecv, pr-> salen), icmp->icmp_seq, ip->ip_ttl, rtt);
	}
	else
	{
		printf(" %d bytes from %s: type = %d, code = %d\n", icmplen, sock_ntop_host(pr->sarecv, pr-> salen), icmp->icmp_type, icmp->icmp_code);
	}
}

////ICMP header is of 8bytes and data we are sending is of 56 bytes total =64 bytes and Kernel adds 20bytes of IP header and attaching it finatl total 84
////therefore when we ping there is "56(84) bytes writter" 84 bytes resembles this total
void send_v4(void)  ////send_v4 is making an ICMP packet and sending it
{
	int len;
	struct icmp *icmp;

	icmp = (struct icmp *) sendbuf;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_id = pid;
	icmp->icmp_seq = nsent++;
	
	gettimeofday((struct timeval *) icmp->icmp_data, NULL);

	len = 8 + datalen; /* checksum ICMP header and data */
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = in_cksum((u_short *) icmp, len); 

	sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);  ////pr->sasend is an address where to send
}



void sig_alrm(int signo)
{
	(*pr->fsend)(); ////fsend is calling send_v4 and send_v4 is making an ICMP packet and sending it
	
	alarm(1);
}

void readloop(void)  ////going in loop receving packet and calling function proc_v4
{
	int size;
	char recvbuf[BUFSIZE];
	socklen_t len;
	ssize_t n;
	struct timeval tval;

	sockfd = socket(pr->sasend->sa_family, SOCK_RAW, pr->icmpproto);

	size = 60 * 1024; /* OK if setsockopt fails */
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

	sig_alrm(SIGALRM); /* send first packet */

	for ( ; ; ) 			
	{
		len = pr->salen;
		n = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, pr->sarecv, &len);  ////recvbuf is an IP packet

		if (n < 0) 
		{
			if (errno == EINTR)          ///EINTR is already defined
				continue;
			else
			{
				printf("recvfrom error\n");
				exit(0);
			}
		}
		//printf("RECFdfdsf");
		//printf("%s",recvbuf); ////////
	
		gettimeofday(&tval, NULL); 

		(*pr->fproc) (recvbuf, n, &tval);
		//printf("RECFdfdsf");
		//printf("%s",recvbuf); ////////
	}
}

int main(int argc, char *argv[])
{
	struct addrinfo *ai;

	host = argv[1];

	pid = getpid();

	signal(SIGALRM, sig_alrm);

	ai = host_serv(host, NULL, 0, 0);

	printf("traceroute to %s (%s), 100 hops max, %d byte packets\n", ai->ai_canonname, sock_ntop_host(ai->ai_addr, ai->ai_addrlen), datalen);

	if(ai->ai_family == AF_INET)
		pr = &proto_v4;					////pr is a pointer to structure and storing the address of proto_v4 which is an object of proto structure 

	pr->sasend = ai->ai_addr;
	pr->sarecv = calloc(1, ai->ai_addrlen);
	pr->salen = ai->ai_addrlen;

	readloop();

	return 0;
}
