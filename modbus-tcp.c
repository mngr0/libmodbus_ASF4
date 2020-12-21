/*
* Copyright © 2001-2013 Stéphane Raimbault <stephane.raimbault@gmail.com>
*
* SPDX-License-Identifier: LGPL-2.1-or-later
*/


// #include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/sys.h"
#include "lwip/api.h"
#include "lwip/tcpip.h"


#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

#if defined(_AIX) && !defined(MSG_DONTWAIT)
#define MSG_DONTWAIT MSG_NONBLOCK
#endif

#include "modbus-private.h"

#include "modbus-tcp.h"
#include "modbus-tcp-private.h"

static int _modbus_set_slave(modbus_t *ctx, int slave)
{
	/* Broadcast address is 0 (MODBUS_BROADCAST_ADDRESS) */
	if (slave >= 0 && slave <= 247) {
		ctx->slave = slave;
		} else if (slave == MODBUS_TCP_SLAVE) {
		/* The special value MODBUS_TCP_SLAVE (0xFF) can be used in TCP mode to
		* restore the default value. */
		ctx->slave = slave;
		} else {
		errno = EINVAL;
		return -1;
	}

	return 0;
}

/* Builds a TCP request header */
static int _modbus_tcp_build_request_basis(modbus_t *ctx, int function,
int addr, int nb,
uint8_t *req)
{
	modbus_tcp_t *ctx_tcp = ctx->backend_data;

	/* Increase transaction ID */
	if (ctx_tcp->t_id < UINT16_MAX)
	ctx_tcp->t_id++;
	else
	ctx_tcp->t_id = 0;
	req[0] = ctx_tcp->t_id >> 8;
	req[1] = ctx_tcp->t_id & 0x00ff;

	/* Protocol Modbus */
	req[2] = 0;
	req[3] = 0;

	/* Length will be defined later by set_req_length_tcp at offsets 4
	and 5 */

	req[6] = ctx->slave;
	req[7] = function;
	req[8] = addr >> 8;
	req[9] = addr & 0x00ff;
	req[10] = nb >> 8;
	req[11] = nb & 0x00ff;

	return _MODBUS_TCP_PRESET_REQ_LENGTH;
}

/* Builds a TCP response header */
static int _modbus_tcp_build_response_basis(sft_t *sft, uint8_t *rsp)
{
	/* Extract from MODBUS Messaging on TCP/IP Implementation
	Guide V1.0b (page 23/46):
	The transaction identifier is used to associate the future
	response with the request. */
	rsp[0] = sft->t_id >> 8;
	rsp[1] = sft->t_id & 0x00ff;

	/* Protocol Modbus */
	rsp[2] = 0;
	rsp[3] = 0;

	/* Length will be set later by send_msg (4 and 5) */

	/* The slave ID is copied from the indication */
	rsp[6] = sft->slave;
	rsp[7] = sft->function;

	return _MODBUS_TCP_PRESET_RSP_LENGTH;
}


static int _modbus_tcp_prepare_response_tid(const uint8_t *req, int *req_length)
{
	return (req[0] << 8) + req[1];
}

static int _modbus_tcp_send_msg_pre(uint8_t *req, int req_length)
{
	/* Substract the header length to the message length */
	int mbap_length = req_length - 6;

	req[4] = mbap_length >> 8;
	req[5] = mbap_length & 0x00FF;

	return req_length;
}

static ssize_t _modbus_tcp_send(modbus_t *ctx, const uint8_t *req, int req_length)
{
	/* MSG_NOSIGNAL
	Requests not to send SIGPIPE on errors on stream oriented
	sockets when the other end breaks the connection.  The EPIPE
	error is still returned. */
	return send(ctx->s, (const char *)req, req_length, MSG_NOSIGNAL);
}

static int _modbus_tcp_receive(modbus_t *ctx, uint8_t *req) {
	return _modbus_receive_msg(ctx, req, MSG_INDICATION);
}

static ssize_t _modbus_tcp_recv(modbus_t *ctx, uint8_t *rsp, int rsp_length) {
	return recv(ctx->s, (char *)rsp, rsp_length, 0);
}

static int _modbus_tcp_check_integrity(modbus_t *ctx, uint8_t *msg, const int msg_length)
{
	return msg_length;
}

static int _modbus_tcp_pre_check_confirmation(modbus_t *ctx, const uint8_t *req,
const uint8_t *rsp, int rsp_length)
{
	/* Check transaction ID */
	if (req[0] != rsp[0] || req[1] != rsp[1]) {
		if (ctx->debug) {
			fprintf(stderr, "Invalid transaction ID received 0x%X (not 0x%X)\n",
			(rsp[0] << 8) + rsp[1], (req[0] << 8) + req[1]);
		}
		errno = EMBBADDATA;
		return -1;
	}

	/* Check protocol ID */
	if (rsp[2] != 0x0 && rsp[3] != 0x0) {
		if (ctx->debug) {
			fprintf(stderr, "Invalid protocol ID received 0x%X (not 0x0)\n",
			(rsp[2] << 8) + rsp[3]);
		}
		errno = EMBBADDATA;
		return -1;
	}

	return 0;
}

static int _modbus_tcp_set_ipv4_options(int s)
{
	int rc;
	int option;

	/* Set the TCP no delay flag */
	/* SOL_TCP = IPPROTO_TCP */
	option = 1;
	rc = setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
	(const void *)&option, sizeof(int));
	if (rc == -1) {
		return -1;
	}

	/* If the OS does not offer SOCK_NONBLOCK, fall back to setting FIONBIO to
	* make sockets non-blocking */
	/* Do not care about the return value, this is optional */
	#if !defined(SOCK_NONBLOCK) && defined(FIONBIO)
	#ifdef OS_WIN32
	{
		/* Setting FIONBIO expects an unsigned long according to MSDN */
		u_long loption = 1;
		ioctlsocket(s, FIONBIO, &loption);
	}
	#else
	option = 1;
	//ioctl(s, FIONBIO, &option);
	#endif
	#endif

	#ifndef OS_WIN32
	/**
	* Cygwin defines IPTOS_LOWDELAY but can't handle that flag so it's
	* necessary to workaround that problem.
	**/
	/* Set the IP low delay option */
	option = IPTOS_LOWDELAY;
	rc = setsockopt(s, IPPROTO_IP, IP_TOS,
	(const void *)&option, sizeof(int));
	if (rc == -1) {
		return -1;
	}
	#endif

	return 0;
}

static int _connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen,
const struct timeval *ro_tv)
{
	int rc = connect(sockfd, addr, addrlen);

	#ifdef OS_WIN32
	int wsaError = 0;
	if (rc == -1) {
		wsaError = WSAGetLastError();
	}

	if (wsaError == WSAEWOULDBLOCK || wsaError == WSAEINPROGRESS) {
		#else
		if (rc == -1 && errno == EINPROGRESS) {
			#endif
			fd_set wset;
			int optval;
			socklen_t optlen = sizeof(optval);
			struct timeval tv = *ro_tv;

			/* Wait to be available in writing */
			FD_ZERO(&wset);
			FD_SET(sockfd, &wset);
			rc = select(sockfd + 1, NULL, &wset, NULL, &tv);
			if (rc <= 0) {
				/* Timeout or fail */
				return -1;
			}

			/* The connection is established if SO_ERROR and optval are set to 0 */
			rc = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (void *)&optval, &optlen);
			if (rc == 0 && optval == 0) {
				return 0;
				} else {
				errno = ECONNREFUSED;
				return -1;
			}
		}
		return rc;
	}

	/* Establishes a modbus TCP connection with a Modbus server. */
	static int _modbus_tcp_connect(modbus_t *ctx)
	{
		int rc;
		/* Specialized version of sockaddr for Internet socket address (same size) */
		struct sockaddr_in addr;
		modbus_tcp_t *ctx_tcp = ctx->backend_data;
		int flags = SOCK_STREAM;

		// #ifdef SOCK_CLOEXEC
		//     flags |= SOCK_CLOEXEC;
		// #endif
		//
		// #ifdef SOCK_NONBLOCK
		//     flags |= SOCK_NONBLOCK;
		// #endif

		ctx->s = socket(PF_INET, flags, 0);
		if (ctx->s == -1) {
			return -1;
		}

		rc = _modbus_tcp_set_ipv4_options(ctx->s);
		if (rc == -1) {
			close(ctx->s);
			ctx->s = -1;
			return -1;
		}

		if (ctx->debug) {
			printf("Connecting to %s:%d\n", ctx_tcp->ip, ctx_tcp->port);
		}

		addr.sin_family = AF_INET;
		addr.sin_port = htons(ctx_tcp->port);
		addr.sin_addr.s_addr = inet_addr(ctx_tcp->ip);
		rc = _connect(ctx->s, (struct sockaddr *)&addr, sizeof(addr), &ctx->response_timeout);
		if (rc == -1) {
			close(ctx->s);
			ctx->s = -1;
			return -1;
		}

		return 0;
	}


	/* Closes the network connection and socket in TCP mode */
	static void _modbus_tcp_close(modbus_t *ctx)
	{
		if (ctx->s != -1) {
			shutdown(ctx->s, SHUT_RDWR);
			close(ctx->s);
			ctx->s = -1;
		}
	}

	static int _modbus_tcp_flush(modbus_t *ctx)
	{
		int rc;
		int rc_sum = 0;

		do {
			/* Extract the garbage from the socket */
			char devnull[MODBUS_TCP_MAX_ADU_LENGTH];
			#ifndef OS_WIN32
			rc = recv(ctx->s, devnull, MODBUS_TCP_MAX_ADU_LENGTH, MSG_DONTWAIT);
			#else
			/* On Win32, it's a bit more complicated to not wait */
			fd_set rset;
			struct timeval tv;

			tv.tv_sec = 0;
			tv.tv_usec = 0;
			FD_ZERO(&rset);
			FD_SET(ctx->s, &rset);
			rc = select(ctx->s+1, &rset, NULL, NULL, &tv);
			if (rc == -1) {
				return -1;
			}

			if (rc == 1) {
				/* There is data to flush */
				rc = recv(ctx->s, devnull, MODBUS_TCP_MAX_ADU_LENGTH, 0);
			}
			#endif
			if (rc > 0) {
				rc_sum += rc;
			}
		} while (rc == MODBUS_TCP_MAX_ADU_LENGTH);

		return rc_sum;
	}

	/* Listens for any request from one or many modbus masters in TCP */
	int modbus_tcp_listen(modbus_t *ctx, int nb_connection)
	{
		int r;
		int enable;
		int flags;
		struct sockaddr_in addr;
		modbus_tcp_t *ctx_tcp;

		if (ctx == NULL) {
			printf("ctx is null\n");
			errno = EINVAL;
			return -1;
		}

		ctx_tcp = ctx->backend_data;

		flags = SOCK_STREAM;


		struct sockaddr_in address;
		int                s_create, new_socket;
		int                addrlen = sizeof(address);
		int                opt     = 1;
		int                socket_check;

		s_create = socket(AF_INET, 1, 0);
		if (s_create == -1) {
			printf("error creating socket\n");
			return -1;
		}
		
		if(s_create == -1){
			printf("wrong at 1\n");
		}
		
		r=setsockopt(s_create, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
		if(r<0){
			printf("ERROR: %d ignored\n",errno);
		}
		if(s_create == -1){
			printf("wrong at 2\n");
		}
		address.sin_family      = AF_INET;
		address.sin_addr.s_addr = htonl(IPADDR_ANY);
		address.sin_port        = htons(502);
		/* bind the connection to port */
		socket_check = bind(s_create, (struct sockaddr *)&address, sizeof(address));
		if (socket_check < 0) {
			printf("bind error\n");
			LWIP_DEBUGF(LWIP_DBG_ON, ("Bind error=%d\n", socket_check));
			close(s_create);
			s_create=-1;
			goto end;
		}
		if(s_create == -1){
			printf("wrong at 3\n");
		}
		/* tell the connection to listen for incoming connection requests */
		listen(s_create, 3);


		if(s_create == -1){
			printf("wrong at 4\n");
		}

		// 		new_s = socket(PF_INET, flags, IPPROTO_TCP);
		// 		if (new_s == -1) {
		// 			printf("error creating socket\n");
		// 			return -1;
		// 		}
		//
		// 		enable = 1;
		// 		if (setsockopt(new_s, SOL_SOCKET, SO_REUSEADDR,
		// 		(char *)&enable, sizeof(enable)) == -1) {
		// 			printf("error calling setsockopt\n");
		// 			close(new_s);
		// 			return -1;
		// 		}
		//
		// 		memset(&addr, 0, sizeof(addr));
		// 		addr.sin_family = AF_INET;
		// 		/* If the modbus port is < to 1024, we need the setuid root. */
		// 		addr.sin_port = htons(ctx_tcp->port);
		// 		if (ctx_tcp->ip[0] == '0') {
		// 			/* Listen any addresses */
		// 			addr.sin_addr.s_addr = htonl(INADDR_ANY);
		// 			} else {
		// 			/* Listen only specified IP address */
		// 			addr.sin_addr.s_addr = inet_addr(ctx_tcp->ip);
		// 		}
		// 		if (bind(new_s, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		// 			printf("error calling bnd\n");
		// 			close(new_s);
		// 			return -1;
		// 		}
		//
		// 		if (listen(new_s, nb_connection) == -1) {
		// 			printf("error calling listen\n");
		// 			close(new_s);
		// 			return -1;
		// 		}

		printf("listen completed\n");
		end:
		printf("returning %d\n",s_create);
		return s_create;
	}


	int modbus_tcp_accept(modbus_t *ctx, int *s)
	{
		struct sockaddr_in addr;
		socklen_t addrlen;
		int new_socket;
		if (ctx == NULL) {
			errno = EINVAL;
			return -1;
		}

		addrlen = sizeof(addr);
		ctx->s = accept(*s, (struct sockaddr *)&addr, &addrlen);

		if (ctx->s == -1) {
			return -1;
		}

		if (ctx->debug) {
			printf("The client connection from %s is accepted\n",
			inet_ntoa(addr.sin_addr));
		}

		return ctx->s;
	}


	static int _modbus_tcp_select(modbus_t *ctx, fd_set *rset, struct timeval *tv, int length_to_read)
	{
		int s_rc;
		while ((s_rc = select(ctx->s+1, rset, NULL, NULL, tv)) == -1) {
			if (errno == EINTR) {
				if (ctx->debug) {
					fprintf(stderr, "A non blocked signal was caught\n");
				}
				/* Necessary after an error */
				FD_ZERO(rset);
				FD_SET(ctx->s, rset);
				} else {
				return -1;
			}
		}

		if (s_rc == 0) {
			errno = ETIMEDOUT;
			return -1;
		}

		return s_rc;
	}

	static void _modbus_tcp_free(modbus_t *ctx) {
		free(ctx->backend_data);
		free(ctx);
	}

	const modbus_backend_t _modbus_tcp_backend = {
		_MODBUS_BACKEND_TYPE_TCP,
		_MODBUS_TCP_HEADER_LENGTH,
		_MODBUS_TCP_CHECKSUM_LENGTH,
		MODBUS_TCP_MAX_ADU_LENGTH,
		_modbus_set_slave,
		_modbus_tcp_build_request_basis,
		_modbus_tcp_build_response_basis,
		_modbus_tcp_prepare_response_tid,
		_modbus_tcp_send_msg_pre,
		_modbus_tcp_send,
		_modbus_tcp_receive,
		_modbus_tcp_recv,
		_modbus_tcp_check_integrity,
		_modbus_tcp_pre_check_confirmation,
		_modbus_tcp_connect,
		_modbus_tcp_close,
		_modbus_tcp_flush,
		_modbus_tcp_select,
		_modbus_tcp_free
	};



	modbus_t* modbus_new_tcp(const char *ip, int port)
	{
		modbus_t *ctx;
		modbus_tcp_t *ctx_tcp;
		size_t dest_size;
		size_t ret_size;

		ctx = (modbus_t *)malloc(sizeof(modbus_t));
		if (ctx == NULL) {
			return NULL;
		}
		_modbus_init_common(ctx);

		/* Could be changed after to reach a remote serial Modbus device */
		ctx->slave = MODBUS_TCP_SLAVE;

		ctx->backend = &_modbus_tcp_backend;

		ctx->backend_data = (modbus_tcp_t *)malloc(sizeof(modbus_tcp_t));
		if (ctx->backend_data == NULL) {
			modbus_free(ctx);
			errno = ENOMEM;
			return NULL;
		}
		ctx_tcp = (modbus_tcp_t *)ctx->backend_data;

		if (ip != NULL) {
			dest_size = sizeof(char) * 16;
			ret_size = strlcpy(ctx_tcp->ip, ip, dest_size);
			if (ret_size == 0) {
				fprintf(stderr, "The IP string is empty\n");
				modbus_free(ctx);
				errno = EINVAL;
				return NULL;
			}

			if (ret_size >= dest_size) {
				fprintf(stderr, "The IP string has been truncated\n");
				modbus_free(ctx);
				errno = EINVAL;
				return NULL;
			}
			} else {
			ctx_tcp->ip[0] = '0';
		}
		ctx_tcp->port = port;
		ctx_tcp->t_id = 0;

		return ctx;
	}
/*

void modbus_routine(void *p){
	printf("starting");
	modbus_t *ctx;
	int socket, new_socket;
	uint8_t query[MODBUS_TCP_MAX_ADU_LENGTH];
	int rc;

	mb_mapping= modbus_mapping_new_start_address(0,20,  50,20,  100,10, 150,10);
	
	sys_sem_t sem;
	err_t     err_sem;
	err_sem = sys_sem_new(&sem, 0); /* Create a new semaphore. */
	tcpip_init(tcpip_init_done, &sem);
	sys_sem_wait(&sem); /* Block until the lwIP stack is initialized. */
	sys_sem_free(&sem); /* Free the semaphore. */
	print_ipaddress();
	

	
	printf("calling newtcp\n");
	ctx = modbus_new_tcp("0.0.0.0", 502);
	ctx->debug=1;
	if(ctx->debug){
		printf("ctx created\n");
	}
	socket = modbus_tcp_listen(ctx, 1);
	if(socket==-1){
		if(ctx->debug){
			printf("errno:%d\n",errno);
			//perror("ciao");
			printf("listen failed \n");
		}
	}
	if(ctx->debug){
		printf("listening\n");
	}

	for (;;) {
		
		new_socket=modbus_tcp_accept(ctx, &socket);
		if(new_socket>0){
			
			if(ctx->debug){
				printf("accepted\n");
			}
			for (;;) {
				rc = modbus_receive(ctx, query);
				if(ctx->debug){
					printf("recved %d\n",rc);
				}
				
				if (rc > 0) {
					if(ctx->debug){
						printf("replying\n");
					}
					modbus_reply(ctx, query, rc, mb_mapping);
				}
				else {
					if(ctx->debug){
						printf("closing 1\n");
					}
					close(new_socket);
					break;
				}
				
			}
		}
		else{
			if(ctx->debug){
				printf("new_socket is %d\n",new_socket);
			}
		}
	}

	modbus_free(ctx);
	
}
*/
