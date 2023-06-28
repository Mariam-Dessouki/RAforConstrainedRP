/* main.c - Application main entry point */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>

#define LOG_LEVEL CONFIG_LOG_DEFAULT_LEVEL
LOG_MODULE_REGISTER(ipsp);

/* Preventing log module registration in net_core.h */
#define NET_LOG_ENABLED	0

#include <zephyr/kernel.h>
#include <zephyr/linker/sections.h>
#include <errno.h>
#include <stdio.h>

#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_context.h>
#include <zephyr/net/udp.h>
#include <zephyr/bluetooth/hci.h>
#include<tinycrypt/cbc_mode.h>
#include<tinycrypt/hmac_prng.h>
#include<tinycrypt/constants.h>

#include <zcbor_encode.h>
#include <zcbor_decode.h>
# include "ar_decoder.h"

/* Define my IP address where to expect messages */
#define MY_IP6ADDR { { { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, \
			 0, 0, 0, 0, 0, 0, 0, 0x1 } } }
#define MY_PREFIX_LEN 64

static struct in6_addr in6addr_my = MY_IP6ADDR;

#define MY_PORT 4242

#define STACKSIZE 2000
K_THREAD_STACK_DEFINE(thread_stack, STACKSIZE);
static struct k_thread thread_data;

static uint8_t buf_tx[NET_IPV6_MTU];

#define MAX_DBG_PRINT 64

NET_PKT_TX_SLAB_DEFINE(echo_tx_tcp, 15);
NET_PKT_DATA_POOL_DEFINE(echo_data_tcp, 30);

static struct k_mem_slab *tx_tcp_pool(void)
{
	return &echo_tx_tcp;
}

static struct net_buf_pool *data_tcp_pool(void)
{
	return &echo_data_tcp;
}

static struct k_sem quit_lock;

static uint8_t id[16] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };

static uint8_t c[16];

static uint8_t iv[16] =
    {
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };

static uint8_t kv[16] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };

static struct tc_hmac_prng_struct prng;
static struct tc_aes_key_sched_struct a;
static int request_sent = 0;

// Test arrays
// static uint8_t test_buf[256] = {0};
// static uint8_t test_data[240] = {0};
// static uint8_t ar_payload[200];

static inline void quit(void)
{
	k_sem_give(&quit_lock);
}

static inline void init_app(void)
{
	LOG_INF("Run IPSP sample");

	k_sem_init(&quit_lock, 0, K_SEM_MAX_LIMIT);

	if (net_addr_pton(AF_INET6,
			  CONFIG_NET_CONFIG_MY_IPV6_ADDR,
			  &in6addr_my) < 0) {
		LOG_ERR("Invalid IPv6 address %s",
			CONFIG_NET_CONFIG_MY_IPV6_ADDR);
	}

	do {
		struct net_if_addr *ifaddr;

		ifaddr = net_if_ipv6_addr_add(net_if_get_default(),
					      &in6addr_my, NET_ADDR_MANUAL, 0);
	} while (0);
}

static inline bool get_context(struct net_context **udp_recv6,
			       struct net_context **tcp_recv6)
{
	int ret;
	struct sockaddr_in6 my_addr6 = { 0 };

	my_addr6.sin6_family = AF_INET6;
	my_addr6.sin6_port = htons(MY_PORT);

	ret = net_context_get(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, udp_recv6);
	if (ret < 0) {
		LOG_ERR("Cannot get network context for IPv6 UDP (%d)", ret);
		return false;
	}

	ret = net_context_bind(*udp_recv6, (struct sockaddr *)&my_addr6,
			       sizeof(struct sockaddr_in6));
	if (ret < 0) {
		LOG_ERR("Cannot bind IPv6 UDP port %d (%d)",
			ntohs(my_addr6.sin6_port), ret);
		return false;
	}

	ret = net_context_get(AF_INET6, SOCK_STREAM, IPPROTO_TCP, tcp_recv6);
	if (ret < 0) {
		LOG_ERR("Cannot get network context for IPv6 TCP (%d)", ret);
		return false;
	}

	net_context_setup_pools(*tcp_recv6, tx_tcp_pool, data_tcp_pool);

	ret = net_context_bind(*tcp_recv6, (struct sockaddr *)&my_addr6,
			       sizeof(struct sockaddr_in6));
	if (ret < 0) {
		LOG_ERR("Cannot bind IPv6 TCP port %d (%d)",
			ntohs(my_addr6.sin6_port), ret);
		return false;
	}

	ret = net_context_listen(*tcp_recv6, 0);
	if (ret < 0) {
		LOG_ERR("Cannot listen IPv6 TCP (%d)", ret);
		return false;
	}

	return true;
}

/*
{
    "eat_profile": "tag:github.com,2023:veraison/ear",
    "iat": 1666529300,
    "ear.verifier-id": {
        "developer": "https://veraison-project.org",
        "build": "vts 0.0.1"
    },
    "submods": {
        "CCA Platform": {
            "ear.status": "affirming"
        }
    }
}
*/ 
// zcbor encoding function added for testing
/*
int encode_zcbor(uint8_t *payload, int payload_len){
	bool ok = 1;
    ZCBOR_STATE_E(state, 0, payload, payload_len, 0);
	ok = zcbor_map_start_encode(state, 20);	// state, max_num: max_num does not affect memory allocation but gives zcbor an expected num
    if(!ok)
        LOG_ERR("Failed to start map");          
    ok &= zcbor_int32_put(state, CBOR_EAT_PROFILE) &&
          zcbor_tstr_put_lit(state, "tag:github.com,2023:veraison/ear");
    if(!ok)
        LOG_ERR("Failed to encode prof"); 
    
    ok &= zcbor_int32_put(state, CBOR_IAT) &&
          zcbor_int64_put(state, 1666529300);
    if(!ok)
        LOG_ERR("Failed to encode iat"); 

    ok &= zcbor_int32_put(state, CBOR_VERIFIER_ID) &&
          zcbor_map_start_encode(state, 4) &&
          zcbor_int32_put(state, CBOR_VERIFIER_DEVELOPER) &&
          zcbor_tstr_put_lit(state, "https://veraison-project.org") &&
          zcbor_int32_put(state, CBOR_VERIFIER_BUILD) &&
          zcbor_tstr_put_lit(state, "vts 0.0.1") &&
          zcbor_map_end_encode(state, 4);
    if(!ok)
        LOG_ERR("Failed to encode verifier"); 

    ok &= zcbor_int32_put(state, CBOR_EAT_SUBMODS) &&
          zcbor_map_start_encode(state, 4) &&
          zcbor_tstr_put_lit(state, "CCA Platform") &&
          zcbor_map_start_encode(state, 4) &&
          zcbor_int32_put(state, CBOR_EAR_STATUS) &&
          zcbor_int32_put(state, 2) &&
          zcbor_map_end_encode(state, 4);
          zcbor_map_end_encode(state, 4);
	ok &= zcbor_map_end_encode(state, 20); //20
    if(!ok) {
        LOG_ERR("Failed to encode submods"); 
		return ok;
	}


    return ok;
}
*/

bool compare_str(const uint8_t *val1, uint8_t *val2, int len)
{
	int cmp = memcmp(val1, val2, len);
	return cmp == 0;
}

int decode_zcbor(uint8_t *payload, int payload_len){

	bool ok = 1;
    struct zcbor_string string;
	int32_t key;
    int64_t iat;

	

    ZCBOR_STATE_D(dec_state, 4, payload, payload_len, 1); // second parameter is how much to remember, last parameter is num of elements
	ok = zcbor_map_start_decode(dec_state);   
	if(!ok){
		LOG_ERR("Failed to start decoder"); 
		return ok;
	}
    ok &= zcbor_int32_decode(dec_state, &key) && key == CBOR_EAT_PROFILE;
    ok &= zcbor_tstr_decode(dec_state, &string) && 
          compare_str(string.value, "tag:github.com,2023:veraison/ear", 32); 
	if(!ok){
		LOG_ERR("Failed to decode profile"); 
		return ok;
	}

    ok &= zcbor_int32_decode(dec_state, &key) && 
          key == CBOR_IAT && 
          zcbor_int64_decode(dec_state, &iat) &&
          iat >= 1666529300;  
	if(!ok){
		LOG_ERR("Failed to decode iat"); 
		return ok;
	}

    ok &= zcbor_int32_decode(dec_state, &key) && 
          key == CBOR_VERIFIER_ID;
    ok &= zcbor_map_start_decode(dec_state);  
    ok &= zcbor_int32_decode(dec_state, &key) && 
          key == CBOR_VERIFIER_DEVELOPER;
    ok &= zcbor_tstr_decode(dec_state, &string) && 
          compare_str(string.value, "https://veraison-project.org", 28); 
    ok &= zcbor_int32_decode(dec_state, &key) && 
          key == CBOR_VERIFIER_BUILD;
    ok &= zcbor_tstr_decode(dec_state, &string) && 
          compare_str(string.value, "vts 0.0.1", strlen("vts 0.0.1")); 
    ok &= zcbor_map_end_decode(dec_state);
	if(!ok){
		LOG_ERR("Failed to decode verifier"); 
		return ok;
	}


    ok &= zcbor_int32_decode(dec_state, &key) && 
          key == CBOR_EAT_SUBMODS;
    ok &= zcbor_map_start_decode(dec_state);  
    ok &= zcbor_tstr_decode(dec_state, &string) && 
          compare_str(string.value, "CCA Platform", strlen("CCA Platform")); 
    ok &= zcbor_map_start_decode(dec_state);  
    ok &= zcbor_int32_decode(dec_state, &key) && 
          key == CBOR_EAR_STATUS;
    ok &= zcbor_int32_decode(dec_state, &key) && 
          key == 2;
    ok &= zcbor_map_end_decode(dec_state);
    ok &= zcbor_map_end_decode(dec_state);
	if(!ok){
		LOG_ERR("Failed to decode submods"); 
		return ok;
	}


	ok &= zcbor_map_end_decode(dec_state);

    return ok;
}

static int prng_reseed(struct tc_hmac_prng_struct *h)
{
	uint8_t seed[32];
	int64_t extra;
	int ret;

	ret = bt_hci_le_rand(seed, sizeof(seed));
	if (ret) {
		return ret;
	}

	extra = k_uptime_get();

	ret = tc_hmac_prng_reseed(h, seed, sizeof(seed), (uint8_t *)&extra,
				  sizeof(extra));
	if (ret == TC_CRYPTO_FAIL) {
		LOG_ERR("Failed to re-seed PRNG");
		return -EIO;
	}

	return 0;
}

int prng_init(void)
{
	uint8_t perso[8];
	int ret = 0;

	ret = bt_hci_le_rand(perso, sizeof(perso));
	if (ret) {
		return ret;
	}

	ret = tc_hmac_prng_init(&prng, perso, sizeof(perso));
	if (ret == TC_CRYPTO_FAIL) {
		LOG_ERR("Failed to initialize PRNG");
		return -EIO;
	}

	/* re-seed is needed after init */
	return prng_reseed(&prng);
}

static int send_message(uint8_t *buf)
{
	// compute hash(k_a) which is not needed for the improved protocol
	/*
	uint8_t id_sha256[32];
    int id_sha256_len = sizeof(id_sha256);
	struct tc_sha256_state_struct s;
	tc_sha256_init(&s);
	tc_sha256_update(&s, ka, sizeof(ka));
	tc_sha256_final(id_sha256, &s);
	*/

	int c_len = sizeof(c);
	uint8_t data[32];
	uint8_t cha[48];
	uint8_t iv_buffer[16];
	int cha_len = sizeof(cha);
	int rc = 0;

	// generating random number
	rc = prng_init();
	if(rc != 0) {
		LOG_ERR("cannot initialize prng: %d", rc);
		return rc;
	}
	tc_hmac_prng_generate(c, c_len, &prng);

	// adding c
	memcpy(data, c, c_len);
	// Concatenating id
	memcpy(data + c_len, id, sizeof(id));

	// generating possible Res value for testing
	/*
	memcpy(test_data, c, c_len);
	memcpy(test_data + c_len, id, sizeof(id));
	// memcpy(test_data + c_len + sizeof(id), id, sizeof(id));
	int payload_len = sizeof(ar_payload);
	bool ok = encode_zcbor(ar_payload, payload_len);
	if(ok){
		LOG_INF("Encode ok");
	}
	memcpy(test_data + c_len + sizeof(id), ar_payload, payload_len);
	memcpy(iv_buffer, iv, TC_AES_BLOCK_SIZE);
	tc_cbc_mode_encrypt(test_buf, sizeof(test_data) + TC_AES_BLOCK_SIZE,
					test_data, sizeof(test_data), iv_buffer, &a);
	*/

	tc_aes128_set_encrypt_key(&a, kv);
	memcpy(iv_buffer, iv, TC_AES_BLOCK_SIZE);
	tc_cbc_mode_encrypt(cha, sizeof(data) + TC_AES_BLOCK_SIZE,
						data, sizeof(data), iv_buffer, &a);
	memcpy(buf, cha, cha_len);
	

	// Test that all is well
	// uint8_t *p = &test_buf[TC_AES_BLOCK_SIZE];
	// int length = sizeof(test_buf) - TC_AES_BLOCK_SIZE;
	// uint8_t data_decrypted[length];
	// tc_aes128_set_decrypt_key(&a, kv);
	// tc_cbc_mode_decrypt(data_decrypted, length, p, length, test_buf, &a);
	// int cmp = memcmp(data_decrypted, test_data, sizeof(test_data));
	// if(cmp == 0)
	// 	LOG_INF("All good... ");
	// else LOG_INF("Not good...");
	request_sent = 1;
	return cha_len;
}

static int receive_message(uint8_t *buf, int buf_size){

	int c_len = sizeof(c);
	int id_len = sizeof(id);

	// changing received buffer value for testing purposes
	/*
	memcpy(buf, test_buf, sizeof(test_buf));
	buf_size = sizeof(test_buf);
	*/

	if(buf_size >= c_len + id_len + TC_AES_BLOCK_SIZE + 1){ // check that there is at least 1 byte for AR 
		uint8_t *p = &buf[TC_AES_BLOCK_SIZE];
		int length = buf_size - TC_AES_BLOCK_SIZE;
		uint8_t data_decrypted[length];
		tc_aes128_set_decrypt_key(&a, kv);
		tc_cbc_mode_decrypt(data_decrypted, length, p, length, buf, &a);
		int ar_len = length - c_len - id_len;
		uint8_t ar[ar_len];


		int cmp = memcmp(data_decrypted, c, c_len);
		if(cmp != 0){
			LOG_ERR("c does not match");
			return -1;
		}
		cmp = memcmp(data_decrypted + c_len, id, id_len);
		if(cmp != 0) {
			LOG_ERR("id does not match");
			return -1;
		}
		
		memcpy(ar, data_decrypted + c_len + id_len, ar_len);
		bool ok = decode_zcbor(ar, ar_len);
		if(ok) {
			LOG_INF("Accepted attestation result");
		} 
		else {
			LOG_INF("Rejected attestation result");
		}
		LOG_INF("All good... ");
		// buf_size = length + c_len;
	}
	else {
		LOG_ERR("Incorrect message size");
		return -1;
	}

	return buf_size;

}

static int build_reply(const char *name,
		       struct net_pkt *pkt,
		       uint8_t *buf)
{
	int reply_len = net_pkt_remaining_data(pkt);
	int ret;

	LOG_DBG("%s received %d bytes", name, reply_len);

	ret = net_pkt_read(pkt, buf, reply_len);
	if (ret < 0) {
		LOG_ERR("cannot read packet: %d", ret);
		return ret;
	}
	// reply_len = sizeof(test_buf);
	// memcpy(buf, test_buf, reply_len);
	if(!request_sent) {
		reply_len = send_message(buf);
	}
	else {
		reply_len = receive_message(buf, reply_len);
	}
	

	LOG_INF("sending %d bytes", reply_len);

	return reply_len;
}

static inline void pkt_sent(struct net_context *context,
			    int status,
			    void *user_data)
{
	if (status >= 0) {
		LOG_DBG("Sent %d bytes", status);
	}
}

static inline void set_dst_addr(sa_family_t family,
				struct net_pkt *pkt,
				struct net_ipv6_hdr *ipv6_hdr,
				struct net_udp_hdr *udp_hdr,
				struct sockaddr *dst_addr)
{
	net_ipv6_addr_copy_raw((uint8_t *)&net_sin6(dst_addr)->sin6_addr,
			       ipv6_hdr->src);
	net_sin6(dst_addr)->sin6_family = AF_INET6;
	net_sin6(dst_addr)->sin6_port = udp_hdr->src_port;
}

static void udp_received(struct net_context *context,
			 struct net_pkt *pkt,
			 union net_ip_header *ip_hdr,
			 union net_proto_header *proto_hdr,
			 int status,
			 void *user_data)
{
	struct sockaddr dst_addr;
	sa_family_t family = net_pkt_family(pkt);
	static char dbg[MAX_DBG_PRINT + 1];
	int ret;

	snprintf(dbg, MAX_DBG_PRINT, "UDP IPv%c",
		 family == AF_INET6 ? '6' : '4');

	set_dst_addr(family, pkt, ip_hdr->ipv6, proto_hdr->udp, &dst_addr);

	ret = build_reply(dbg, pkt, buf_tx);
	if (ret < 0) {
		LOG_ERR("Cannot send data to peer (%d)", ret);
		return;
	}

	net_pkt_unref(pkt);

	ret = net_context_sendto(context, buf_tx, ret, &dst_addr,
				 family == AF_INET6 ?
				 sizeof(struct sockaddr_in6) :
				 sizeof(struct sockaddr_in),
				 pkt_sent, K_NO_WAIT, user_data);
	if (ret < 0) {
		LOG_ERR("Cannot send data to peer (%d)", ret);
	}
}

static void setup_udp_recv(struct net_context *udp_recv6)
{
	int ret;

	ret = net_context_recv(udp_recv6, udp_received, K_NO_WAIT, NULL);
	if (ret < 0) {
		LOG_ERR("Cannot receive IPv6 UDP packets");
	}
}

static void tcp_received(struct net_context *context,
			 struct net_pkt *pkt,
			 union net_ip_header *ip_hdr,
			 union net_proto_header *proto_hdr,
			 int status,
			 void *user_data)
{
	static char dbg[MAX_DBG_PRINT + 1];
	sa_family_t family;
	int ret, len;

	if (!pkt) {
		/* EOF condition */
		return;
	}

	family = net_pkt_family(pkt);
	len = net_pkt_remaining_data(pkt);

	snprintf(dbg, MAX_DBG_PRINT, "TCP IPv%c",
		 family == AF_INET6 ? '6' : '4');

	ret = build_reply(dbg, pkt, buf_tx);
	if (ret < 0) {
		LOG_ERR("Cannot send data to peer (%d)", ret);
		return;
	}

	(void)net_context_update_recv_wnd(context, len);
	net_pkt_unref(pkt);

	ret = net_context_send(context, buf_tx, ret, pkt_sent,
			       K_NO_WAIT, NULL);
	if (ret < 0) {
		LOG_ERR("Cannot send data to peer (%d)", ret);
		quit();
	}
}

static void tcp_accepted(struct net_context *context,
			 struct sockaddr *addr,
			 socklen_t addrlen,
			 int error,
			 void *user_data)
{
	int ret;

	NET_DBG("Accept called, context %p error %d", context, error);

	net_context_set_accepting(context, false);

	ret = net_context_recv(context, tcp_received, K_NO_WAIT, NULL);
	if (ret < 0) {
		LOG_ERR("Cannot receive TCP packet (family %d)",
			net_context_get_family(context));
	}
}

static void setup_tcp_accept(struct net_context *tcp_recv6)
{
	int ret;

	ret = net_context_accept(tcp_recv6, tcp_accepted, K_NO_WAIT, NULL);
	if (ret < 0) {
		LOG_ERR("Cannot receive IPv6 TCP packets (%d)", ret);
	}
}

static void listen(void)
{
	struct net_context *udp_recv6 = { 0 };
	struct net_context *tcp_recv6 = { 0 };

	if (!get_context(&udp_recv6, &tcp_recv6)) {
		LOG_ERR("Cannot get network contexts");
		return;
	}

	LOG_INF("Starting to wait");

	setup_tcp_accept(tcp_recv6);
	setup_udp_recv(udp_recv6);

	k_sem_take(&quit_lock, K_FOREVER);

	LOG_INF("Stopping...");

	net_context_put(udp_recv6);
	net_context_put(tcp_recv6);
}

int main(void)
{
	init_app();

	k_thread_create(&thread_data, thread_stack, STACKSIZE,
			(k_thread_entry_t)listen,
			NULL, NULL, NULL, K_PRIO_COOP(7), 0, K_NO_WAIT);
	return 0;
}
