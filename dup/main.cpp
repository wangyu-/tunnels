#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<stdlib.h>
#include<getopt.h>
#include <unistd.h>
#include<errno.h>

#include <fcntl.h>
//#include"aes.h"

#include <sys/epoll.h>
#include <sys/wait.h>

#include<map>
#include<string>
#include<vector>
using namespace std;

map<string, string> mp;

char local_address[100], remote_address[100];
int local_port = -1, remote_port = -1;
//char keya[100], keyb[100];
int dup_a = 1, dup_b = 1;
char iv[100];
const int buf_len = 20480;

void handler(int num) {
	int status;
	int pid;
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (WIFEXITED(status)) {
			//printf("The child exit with code %d",WEXITSTATUS(status));
		}
	}

}
void encrypt(char * input, int len, char *key) {
	int i, j;
	//char tmp[buf_len];
	//len=len/16*16+1;
	//AES128_CBC_encrypt_buffer((uint8_t *)tmp, (uint8_t *)input, len, (uint8_t *)key, (uint8_t *)iv);
	for (i = 0, j = 0; i < len; i++, j++) {
		if (key[j] == 0)
			j = 0;
		input[i] ^= key[j];
	}
}
void decrypt(char * input, int len, char *key) {
	int i, j;
	//char tmp[buf_len];
	//len=len/16*16+1;
	//AES128_CBC_decrypt_buffer((uint8_t *)tmp, (uint8_t *)input, len, (uint8_t *)key, (uint8_t *)iv);
	//for(i=0;i<len;i++)
	//input[i]=tmp[i];
	for (i = 0, j = 0; i < len; i++, j++) {
		if (key[j] == 0)
			j = 0;
		input[i] ^= key[j];
	}
}
void setnonblocking(int sock) {
	int opts;
	opts = fcntl(sock, F_GETFL);

	if (opts < 0) {
		perror("fcntl(sock,GETFL)");
		exit(1);
	}

	opts = opts | O_NONBLOCK;
	if (fcntl(sock, F_SETFL, opts) < 0) {
		perror("fcntl(sock,SETFL,opts)");
		exit(1);
	}

}
int main(int argc, char *argv[]) {
	int i, j, k;
	int opt;
	signal(SIGCHLD, handler);

	printf("argc=%d ", argc);
	for (i = 0; i < argc; i++)
		printf("%s ", argv[i]);
	printf("\n");
	//memset(keya, 0, sizeof(keya));
	//memset(keyb, 0, sizeof(keyb));
	memset(iv, 0, sizeof(iv));
	strcpy(iv, "1234567890abcdef");
	if (argc == 1) {
		printf(
				"proc -l [adress:]port -r [adress:]port  [-a dup_time] [-b dup_time]\n");
		return -1;
	}
	int no_l = 1, no_r = 1;
	while ((opt = getopt(argc, argv, "l:r:a:b:h")) != -1) {
		//string opt_key;
		//opt_key+=opt;
		switch (opt) {
		case 'l':
			no_l = 0;
			if (strchr(optarg, ':') != 0) {
				sscanf(optarg, "%[^:]:%d", local_address, &local_port);
			} else {
				strcpy(local_address, "127.0.0.1");
				sscanf(optarg, "%d", &local_port);
			}
			break;
		case 'r':
			no_r = 0;
			if (strchr(optarg, ':') != 0) {
				//printf("in :\n");
				//printf("%s\n",optarg);
				sscanf(optarg, "%[^:]:%d", remote_address, &remote_port);
				//printf("%d\n",remote_port);
			} else {
				strcpy(remote_address, "127.0.0.1");
				sscanf(optarg, "%d", &remote_port);
			}
			break;
		case 'a':
			sscanf(optarg, "%d", &dup_a);
			//strcpy(keya, optarg);
			break;
		case 'b':
			sscanf(optarg, "%d", &dup_b);
			//strcpy(keyb, optarg);
			break;
		case 'h':
			break;
		default:
			printf("ignore unknown <%s>", optopt);
		}
	}

	if (no_l)
		printf("error: -i not found\n");
	if (no_r)
		printf("error: -o not found\n");
	if (no_l || no_r) {
		exit(-1);
	}

	struct sockaddr_in local_me, local_other;
	int local_listen_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	int yes = 1;
	setsockopt(local_listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

	char buf[buf_len];
	socklen_t slen = sizeof(sockaddr_in);
	memset(&local_me, 0, sizeof(local_me));
	local_me.sin_family = AF_INET;
	local_me.sin_port = htons(local_port);
	local_me.sin_addr.s_addr = inet_addr(local_address);
	if (bind(local_listen_fd, (struct sockaddr*) &local_me, slen) == -1) {
		printf("socket bind error");
		exit(1);
	}
	while (1) {
		socklen_t recv_len;
		if ((recv_len = recvfrom(local_listen_fd, buf, buf_len, 0,
				(struct sockaddr *) &local_other, &slen)) == -1) //<--first packet from a new ip:port turple
				{
			printf("recv_from error");
			exit(1);
		}
		printf("Received packet from %s:%d\n", inet_ntoa(local_other.sin_addr),
				ntohs(local_other.sin_port));

		buf[recv_len] = 0;
		printf("recv_len: %d\n", recv_len);
		fflush(stdout);
		//printf("Data: %s\n" , buf);
		int local_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		//local_me.sin_addr.s_addr=inet_addr("127.0.0.1");
		setsockopt(local_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
		if (bind(local_fd, (struct sockaddr*) &local_me, slen) == -1) {
			printf("socket bind error in chilld");
			exit(1);
		}
		int ret = connect(local_fd, (struct sockaddr *) &local_other, slen); //父进程替子进程做
		if (fork() == 0)  //子
				{
			if (ret != 0) {
				printf("connect return %d @1\n", ret);
				exit(1);
			}
			close(local_listen_fd);

			struct sockaddr_in remote_me, remote_other;

			memset(&remote_other, 0, sizeof(remote_other));
			remote_other.sin_family = AF_INET;
			//printf("remote_address=%s  remote_port=%d\n",remote_address,remote_port);
			remote_other.sin_port = htons(remote_port);
			remote_other.sin_addr.s_addr = inet_addr(remote_address);
			int remote_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			ret = connect(remote_fd, (struct sockaddr *) &remote_other, slen);
			if (ret != 0) {
				printf("connect return %d @2\n", ret);
				exit(1);
			}

			for (int i = 0; i < dup_b; i++) {
				ret = send(remote_fd, buf, recv_len, 0); //<----send the packet receved by father process  ,only for this packet

				printf("send return %d\n", ret);
				if (ret < 0)
					exit(-1);
			}

			setnonblocking(remote_fd);
			setnonblocking(local_fd);
			int epollfd = epoll_create1(0);
			const int max_events = 4096;
			struct epoll_event ev, events[max_events];
			if (epollfd < 0) {
				printf("epoll return %d\n", epollfd);
				exit(-1);
			}
			ev.events = EPOLLIN;
			ev.data.fd = local_fd;
			ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, local_fd, &ev);
			if (ret < 0) {
				printf("epoll_ctl return %d\n", ret);
				exit(-1);
			}
			ev.events = EPOLLIN;
			ev.data.fd = remote_fd;
			ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, remote_fd, &ev);
			if (ret < 0) {
				printf("epoll_ctl return %d\n", ret);
				exit(-1);
			}
			for (;;) {
				int nfds = epoll_wait(epollfd, events, max_events, 60 * 1000);
				if (nfds <= 0) {
					printf("epoll_wait return %d\n", nfds);
					exit(-1);
				}
				int n;
				for (n = 0; n < nfds; ++n) {
					if (events[n].data.fd == local_fd) //data income from local end
							{
						recv_len = recv(local_fd, buf, buf_len, 0);
						if (recv_len < 0) {
							printf("recv return %d @1", recv_len);
							exit(1);
						}

						buf[recv_len] = 0;
						printf("len %d received from child@1\n", recv_len);
						//printf("%s received from child@1\n",buf);

						//printf("before send %s\n",buf);
						for (int i = 0; i < dup_b; i++) {
							ret = send(remote_fd, buf, recv_len, 0);
							if (ret < 0) {
								printf("send return %d at @1", ret);
								exit(1);
							}
							printf("send return %d @1\n", ret);
						}
					} else if (events[n].data.fd == remote_fd) {
						recv_len = recv(remote_fd, buf, buf_len, 0);
						if (recv_len < 0) {
							printf("recv return -1 @2", recv_len);
							exit(1);
						}

						buf[recv_len] = 0;
						printf("len %d received from child@1\n", recv_len);
						//printf("%s received from child@2\n",buf);
						for (int i = 0; i < dup_a; i++) {
							ret = send(local_fd, buf, recv_len, 0);
							if (ret < 0) {
								printf("send return %d @2", ret);
								exit(1);
							}
							printf("send return %d @2\n", ret);
						}
					}
				}
			}
			exit(0);
		} else //if(fork()==0)  ... else
		{ //fork 's father process
			close(local_fd); //father process only listen to local_listen_fd,so,close this fd
		}
	}  //while(1)end

	return 0;
}
