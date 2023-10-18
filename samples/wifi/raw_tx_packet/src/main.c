/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/** @file
 * @brief WiFi tx packet sample
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(tx_packet, CONFIG_LOG_DEFAULT_LEVEL);

#include <nrfx_clock.h>
#include <zephyr/kernel.h>
#include <stdio.h>
#include <stdlib.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/printk.h>
#include <zephyr/init.h>

#include <zephyr/net/net_if.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/net_event.h>
#include <zephyr/drivers/gpio.h>

#include <qspi_if.h>

#include "net_private.h"

#define WIFI_SHELL_MODULE "wifi"

#define WIFI_SHELL_MGMT_EVENTS (NET_EVENT_WIFI_CONNECT_RESULT |		\
				NET_EVENT_WIFI_DISCONNECT_RESULT)

#define MAX_SSID_LEN        32
#define STATUS_POLLING_MS   300

/* 1000 msec = 1 sec */
#define LED_SLEEP_TIME_MS   100

/* The devicetree node identifier for the "led0" alias. */
#define LED0_NODE DT_ALIAS(led0)
/*
 * A build error on this line means your board is unsupported.
 * See the sample documentation for information on how to fix this.
 */
static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(LED0_NODE, gpios);

#define RECV_BUFFER_SIZE 1000
struct packet_data {
        int send_sock;
        int recv_sock;
        char recv_buffer[RECV_BUFFER_SIZE];
};

static struct net_mgmt_event_callback wifi_shell_mgmt_cb;
static struct net_mgmt_event_callback net_shell_mgmt_cb;

static struct {
	const struct shell *sh;
	union {
		struct {
			uint8_t connected	: 1;
			uint8_t connect_result	: 1;
			uint8_t disconnect_requested	: 1;
			uint8_t _unused		: 5;
		};
		uint8_t all;
	};
} context;

void toggle_led(void)
{
	int ret;

	if (!device_is_ready(led.port)) {
		LOG_ERR("LED device is not ready");
		return;
	}

	ret = gpio_pin_configure_dt(&led, GPIO_OUTPUT_ACTIVE);
	if (ret < 0) {
		LOG_ERR("Error %d: failed to configure LED pin", ret);
		return;
	}

	while (1) {
		if (context.connected) {
			gpio_pin_toggle_dt(&led);
			k_msleep(LED_SLEEP_TIME_MS);
		} else {
			gpio_pin_set_dt(&led, 0);
			k_msleep(LED_SLEEP_TIME_MS);
		}
	}
}

K_THREAD_DEFINE(led_thread_id, 1024, toggle_led, NULL, NULL, NULL,
		7, 0, 0);

static int cmd_wifi_status(void)
{
	struct net_if *iface = net_if_get_default();
	struct wifi_iface_status status = { 0 };

	if (net_mgmt(NET_REQUEST_WIFI_IFACE_STATUS, iface, &status,
				sizeof(struct wifi_iface_status))) {
		LOG_INF("Status request failed");

		return -ENOEXEC;
	}

	LOG_INF("==================");
	LOG_INF("State: %s", wifi_state_txt(status.state));

	if (status.state >= WIFI_STATE_ASSOCIATED) {
		uint8_t mac_string_buf[sizeof("xx:xx:xx:xx:xx:xx")];

		LOG_INF("Interface Mode: %s",
		       wifi_mode_txt(status.iface_mode));
		LOG_INF("Link Mode: %s",
		       wifi_link_mode_txt(status.link_mode));
		LOG_INF("SSID: %-32s", status.ssid);
		LOG_INF("BSSID: %s",
		       net_sprint_ll_addr_buf(
				status.bssid, WIFI_MAC_ADDR_LEN,
				mac_string_buf, sizeof(mac_string_buf)));
		LOG_INF("Band: %s", wifi_band_txt(status.band));
		LOG_INF("Channel: %d", status.channel);
		LOG_INF("Security: %s", wifi_security_txt(status.security));
		LOG_INF("MFP: %s", wifi_mfp_txt(status.mfp));
		LOG_INF("RSSI: %d", status.rssi);
	}
	return 0;
}

static void handle_wifi_connect_result(struct net_mgmt_event_callback *cb)
{
	const struct wifi_status *status =
		(const struct wifi_status *) cb->info;

	if (context.connected) {
		return;
	}

	if (status->status) {
		LOG_ERR("Connection failed (%d)", status->status);
	} else {
		LOG_INF("Connected");
		context.connected = true;
	}

	context.connect_result = true;
}

static void handle_wifi_disconnect_result(struct net_mgmt_event_callback *cb)
{
	const struct wifi_status *status =
		(const struct wifi_status *) cb->info;

	if (!context.connected) {
		return;
	}

	if (context.disconnect_requested) {
		LOG_INF("Disconnection request %s (%d)",
			 status->status ? "failed" : "done",
					status->status);
		context.disconnect_requested = false;
	} else {
		LOG_INF("Received Disconnected");
		context.connected = false;
	}

	cmd_wifi_status();
}

static void wifi_mgmt_event_handler(struct net_mgmt_event_callback *cb,
				     uint32_t mgmt_event, struct net_if *iface)
{
	switch (mgmt_event) {
	case NET_EVENT_WIFI_CONNECT_RESULT:
		handle_wifi_connect_result(cb);
		break;
	case NET_EVENT_WIFI_DISCONNECT_RESULT:
		handle_wifi_disconnect_result(cb);
		break;
	default:
		break;
	}
}

static void print_dhcp_ip(struct net_mgmt_event_callback *cb)
{
	/* Get DHCP info from struct net_if_dhcpv4 and print */
	const struct net_if_dhcpv4 *dhcpv4 = cb->info;
	const struct in_addr *addr = &dhcpv4->requested_ip;
	char dhcp_info[128];

	net_addr_ntop(AF_INET, addr, dhcp_info, sizeof(dhcp_info));

	LOG_INF("DHCP IP address: %s", dhcp_info);
}
static void net_mgmt_event_handler(struct net_mgmt_event_callback *cb,
				    uint32_t mgmt_event, struct net_if *iface)
{
	switch (mgmt_event) {
	case NET_EVENT_IPV4_DHCP_BOUND:
		print_dhcp_ip(cb);
		break;
	default:
		break;
	}
}

static int __wifi_args_to_params(struct wifi_connect_req_params *params)
{

	params->timeout =  CONFIG_STA_CONN_TIMEOUT_SEC * MSEC_PER_SEC;

	if (params->timeout == 0) {
		params->timeout = SYS_FOREVER_MS;
	}

	/* SSID */
	params->ssid = CONFIG_STA_SAMPLE_SSID;
	params->ssid_length = strlen(params->ssid);

#if defined(CONFIG_STA_KEY_MGMT_WPA2)
	params->security = 1;
#elif defined(CONFIG_STA_KEY_MGMT_WPA2_256)
	params->security = 2;
#elif defined(CONFIG_STA_KEY_MGMT_WPA3)
	params->security = 3;
#else
	params->security = 0;
#endif

#if !defined(CONFIG_STA_KEY_MGMT_NONE)
	params->psk = CONFIG_STA_SAMPLE_PASSWORD;
	params->psk_length = strlen(params->psk);
#endif
	params->channel = WIFI_CHANNEL_ANY;

	/* MFP (optional) */
	params->mfp = WIFI_MFP_OPTIONAL;

	return 0;
}

static int wifi_connect(void)
{
	struct net_if *iface = net_if_get_default();
	static struct wifi_connect_req_params cnx_params;

	context.connected = false;
	context.connect_result = false;
	__wifi_args_to_params(&cnx_params);

	if (net_mgmt(NET_REQUEST_WIFI_CONNECT, iface,
		     &cnx_params, sizeof(struct wifi_connect_req_params))) {
		LOG_ERR("Connection request failed");

		return -ENOEXEC;
	}

	LOG_INF("Connection requested");

	return 0;
}

int bytes_from_str(const char *str, uint8_t *bytes, size_t bytes_len)
{
	size_t i;
	char byte_str[3];

	if (strlen(str) != bytes_len * 2) {
		LOG_ERR("Invalid string length: %zu (expected: %d)\n",
			strlen(str), bytes_len * 2);
		return -EINVAL;
	}

	for (i = 0; i < bytes_len; i++) {
		memcpy(byte_str, str + i * 2, 2);
		byte_str[2] = '\0';
		bytes[i] = strtol(byte_str, NULL, 16);
	}

	return 0;
}

static int wifi_set_channel(void)
{
	struct net_if *iface;
	struct wifi_channel_info channel_info = {0};
	int ret;

	channel_info.oper = WIFI_MGMT_SET;

	if (channel_info.if_index == 0) {
		iface = net_if_get_first_wifi();
		if (iface == NULL) {
			LOG_ERR("Cannot find the default wifi interface\n");
			return -ENOEXEC;
		}
		channel_info.if_index = net_if_get_by_iface(iface);
	} else {
		iface = net_if_get_by_index(channel_info.if_index);
		if (iface == NULL) {
			LOG_ERR("Cannot find interface for if_index %d\n",
					      channel_info.if_index);
			return -ENOEXEC;
		}
	}

		
	if (channel_info.oper == WIFI_MGMT_SET) {
		channel_info.channel = CONFIG_RAW_TX_PACKET_APP_CHANNEL;
		if ((channel_info.channel < WIFI_CHANNEL_MIN) ||
			   (channel_info.channel > WIFI_CHANNEL_MAX)) {
				LOG_ERR("Invalid channel number. Range is (1-233)\n");
				return -ENOEXEC;
		}
	}

	ret = net_mgmt(NET_REQUEST_WIFI_CHANNEL, iface,
			&channel_info, sizeof(channel_info));

	if (ret) {
		LOG_ERR("channel set operation failed with reason %d\n", ret);
			return -ENOEXEC;
	}

	LOG_INF("Wi-Fi channel set to %d\n", channel_info.channel);

	return 0;
}


void wifi_set_mode(void)
{
	struct net_if *iface;
	struct wifi_mode_info mode_info = {0};

	mode_info.oper = WIFI_MGMT_SET;
	if (mode_info.if_index == 0) {
		iface = net_if_get_first_wifi();
		if (iface == NULL) {
			LOG_ERR("Cannot find the default wifi interface\n");
			return;
		}
		mode_info.if_index = net_if_get_by_iface(iface);
	} else {
		iface = net_if_get_by_index(mode_info.if_index);
		if (iface == NULL) {
			LOG_ERR("Cannot find interface for if_index %d\n",
				      mode_info.if_index);
			return;
		}
	}

	mode_info.mode =  WIFI_STA_MODE | WIFI_TX_INJECTION_MODE ;

	if (net_mgmt(NET_REQUEST_WIFI_MODE, iface, &mode_info, sizeof(mode_info)))
		LOG_ERR("Mode set operation failed");

}

#if 0
int wifi_send_data(void) {

	int sock, ret;
	struct sockaddr_in addr;
	char buffer[] = "Hello";

	sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (sock < 0) {
                printk("Failed to create raw socket : %d\n", errno);
                return -errno;
        } else {
                printk("raw socket created \n");
        }

	addr.sin_family = AF_PACKET;
	addr.sin_port=IN_ANY;
	addr.sin_addr.s_addr = INADDR_ANY;

	ret = bind(sock, (struct sockaddr *)&addr,
                   sizeof(struct sockaddr_in));
	if (ret < 0) {
                printk("Failed to bind packet socket : %d\n", errno);
                return -errno;
        } else {
                printk("bind packet successful\n");
        }

	ret = sendto(sock, buffer, 4, 0,
                             (struct sockaddr *)&addr,
                             sizeof(struct sockaddr_in));
	if (ret < 0) {
                printk("Failed to send, errno %d\n", errno);
        } else {
                printk("send successful\n");
        }

	return 0;
}
#endif

#define SERVER_IP "192.168.0.100"  // Replace with your server's IP address
#define SERVER_PORT 8080           // Replace with your server's port
#define DATA_INTERVAL K_SECONDS(1) // Data send interval
#define BEACON_FRAME_LEN 100       // Length of your beacon frame

struct nrf_wifi_fmac_rawpkt_info {
        /** Magic number to distinguish packet is raw packet */
        unsigned int magic_number;
        /** Data rate of the packet */
        unsigned char data_rate;
        /** Packet length */
        unsigned short packet_length;
        /** Mode describing if packet is VHT, HT, HE or Legacy */
        unsigned char tx_mode;
        /** Wi-Fi access category mapping for packet */
        unsigned char queue;
        /** reserved parameter for driver */
        unsigned char reserved;
};

/* SSID: NRF_RAW_TX_PACKET_APP */
/* 0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xa0, 0x59, 0x50, 0xe3, 0x52, 0x15,*/
char beacon_frame[] = {
0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xa0, 0x69, 0x60, 0xe3, 0x52, 0x15,
0xa0, 0x59, 0x50, 0xe3, 0x52, 0x15, 0xb0, 0x53,

0xf0, 0xcf, 0x29, 0x8e, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x11, 0x04, 0x00, 0x15, 0x4E, 0x52,
0x46, 0x5F, 0x52, 0x41, 0x57, 0x5F, 0x54, 0x58, 0x5F, 0x50, 0x41, 0x43, 0x4B, 0x45, 0x54, 0x5F,
0x41, 0x50, 0x50, 0x54, 0x72, 0x61, 0x63, 0x6b, 0x5f, 0x31, 0x36, 0x38, 0x36, 0x31, 0x32, 0x32,
0x38, 0x36, 0x35, 0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24, 0x03, 0x01, 0x06,
0x05, 0x04, 0x00, 0x02, 0x00, 0x00, 0x2a, 0x01, 0x04, 0x32, 0x04, 0x30, 0x48, 0x60, 0x6c, 0x30,
0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00,
0x0f, 0xac, 0x02, 0xcc, 0x00, 0x3b, 0x02, 0x51, 0x00, 0x2d, 0x1a, 0x0c, 0x00, 0x17, 0xff, 0xff,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x3d, 0x16, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x08, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00,
0x00, 0x40, 0xff, 0x1a, 0x23, 0x01, 0x78, 0x10, 0x1a, 0x00, 0x00, 0x00, 0x20, 0x0e, 0x09, 0x00,
0x09, 0x80, 0x04, 0x01, 0xc4, 0x00, 0xfa, 0xff, 0xfa, 0xff, 0x61, 0x1c, 0xc7, 0x71, 0xff, 0x07,
0x24, 0xf0, 0x3f, 0x00, 0x81, 0xfc, 0xff, 0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x01,
0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4, 0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00
};

void wifi_send_data(void)
{
    struct sockaddr_ll sa;
    int sockfd, ret;
    struct net_iface *iface;
    struct nrf_wifi_fmac_rawpkt_info raw_tx_pkt;
    char *buffer = NULL;
    int num_frames, buf_length;

    /* Create a raw socket */
    sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        printk("Error: Unable to create socket\n");
        return;
    }

     iface = net_if_get_first_wifi();

     sa.sll_family = AF_PACKET;
     sa.sll_protocol = htons(ETH_P_ALL); // Ethernet protocol (e.g., ETH_P_IP)
     sa.sll_ifindex = net_if_get_by_iface(iface);


    /* Bind the socket */
    ret = bind(sockfd, (struct sockaddr *)&sa, sizeof(struct sockaddr_ll));
    if (ret < 0) {
        printk("Error: Unable to bind socket to the network interface:%d\n", errno);
        close(sockfd);
        return;
    }

    raw_tx_pkt.magic_number = 0x12345678; // Set magic number to identify raw packet
    raw_tx_pkt.data_rate = CONFIG_RAW_TX_PACKET_APP_RATE_VALUE; // Set the desired rate value
    raw_tx_pkt.packet_length = sizeof(beacon_frame); // Length of the packet
    raw_tx_pkt.tx_mode = CONFIG_RAW_TX_PACKET_APP_RATE_FLAGS; // Rate flags
    raw_tx_pkt.queue = CONFIG_RAW_TX_PACKET_APP_QUEUE_NUM; // Set appropriate queue number
    raw_tx_pkt.reserved = 0; // Reserved bit


    buffer = malloc(sizeof(struct nrf_wifi_fmac_rawpkt_info) + sizeof(beacon_frame));
    if(!buffer)
	    return;

    LOG_INF("%s: Beacon buf size :%d", __func__, sizeof(beacon_frame));

    buf_length = sizeof(struct nrf_wifi_fmac_rawpkt_info) + sizeof(beacon_frame);

    LOG_INF("%s: Buffer size :%d", __func__, buf_length);
   
    memcpy(buffer, &raw_tx_pkt, sizeof(struct nrf_wifi_fmac_rawpkt_info));


    memcpy(buffer + sizeof(struct nrf_wifi_fmac_rawpkt_info), beacon_frame, sizeof(beacon_frame));

#ifdef CONFIG_RAW_TX_PACKET_APP_CONTINUOUS
	num_frames = -1;
	LOG_INF("Continuous mode transmission");
#else
	num_frames = CONFIG_RAW_TX_PACKET_APP_NUM_PACKETS;
	LOG_INF("%d number of frames transmission", num_frames);
#endif

	while (1) {
#ifndef CONFIG_RAW_TX_PACKET_APP_CONTINUOUS
		if (num_frames == 0) {
			LOG_INF("0 number of frames selected");
			break;
		}
#endif
		
        	ret = sendto(sockfd, buffer, buf_length, 0,
                 	     (struct sockaddr *)&sa, sizeof(sa));
        	if (ret < 0) {
            		printk("Error: Unable to send beacon frame\n");
            		close(sockfd);
			free(buffer);
            		return;
        	}

#ifndef CONFIG_RAW_TX_PACKET_APP_CONTINUOUS
		if (num_frames > 0) {
			num_frames --;
		}
#endif

#if 0 
		/* Check beacon frame or not */
    		// Check frame control field (first two bytes)
    		if ((beacon_frame[0] != 0x80) || (buffer[1] != 0x00)) {
            		LOG_INF("TRIVENI: Not a beacon frame");
#ifdef CONFIG_RAW_TX_PACKET_APP_INTER_FRAME_DELAY
			k_sleep(K_USEC(CONFIG_RAW_TX_PACKET_APP_INTER_FRAME_DELAY));
#endif
    		} else { 
            		LOG_INF("TRIVENI: It is a beacon frame");
			k_sleep(K_MSEC(100));
		}
#endif
		k_sleep(K_MSEC(100));
	}

    /* close the socket */
    close(sockfd);
    free(buffer);
}

int main(void)
{
	memset(&context, 0, sizeof(context));

	net_mgmt_init_event_callback(&wifi_shell_mgmt_cb,
				     wifi_mgmt_event_handler,
				     WIFI_SHELL_MGMT_EVENTS);

	net_mgmt_add_event_callback(&wifi_shell_mgmt_cb);


	net_mgmt_init_event_callback(&net_shell_mgmt_cb,
				     net_mgmt_event_handler,
				     NET_EVENT_IPV4_DHCP_BOUND);

	net_mgmt_add_event_callback(&net_shell_mgmt_cb);

	LOG_INF("Starting %s with CPU frequency: %d MHz", CONFIG_BOARD, SystemCoreClock/MHZ(1));
	k_sleep(K_SECONDS(1));

#if defined(CONFIG_BOARD_NRF7002DK_NRF7001_NRF5340_CPUAPP) || \
	defined(CONFIG_BOARD_NRF7002DK_NRF5340_CPUAPP)
	if (strlen(CONFIG_NRF700X_QSPI_ENCRYPTION_KEY)) {
		char key[QSPI_KEY_LEN_BYTES];
		int ret;

		ret = bytes_from_str(CONFIG_NRF700X_QSPI_ENCRYPTION_KEY, key, sizeof(key));
		if (ret) {
			LOG_ERR("Failed to parse encryption key: %d\n", ret);
			return 0;
		}

		LOG_DBG("QSPI Encryption key: ");
		for (int i = 0; i < QSPI_KEY_LEN_BYTES; i++) {
			LOG_DBG("%02x", key[i]);
		}
		LOG_DBG("\n");

		ret = qspi_enable_encryption(key);
		if (ret) {
			LOG_ERR("Failed to enable encryption: %d\n", ret);
			return 0;
		}
		LOG_INF("QSPI Encryption enabled");
	} else {
		LOG_INF("QSPI Encryption disabled");
	}
#endif /* CONFIG_BOARD_NRF700XDK_NRF5340 */

	LOG_INF("Static IP address (overridable): %s/%s -> %s",
		CONFIG_NET_CONFIG_MY_IPV4_ADDR,
		CONFIG_NET_CONFIG_MY_IPV4_NETMASK,
		CONFIG_NET_CONFIG_MY_IPV4_GW);

	/* Set mode */
	wifi_set_mode();
	/* Wait timeout for mode to be set
	 * Can be decreased after testing
	 */
	k_sleep(K_SECONDS(5));

#ifdef CONFIG_CONNECTION_MODE
	/* Connect to an AP */
	wifi_connect();
	/* Timeout to wiat for connection */
	k_sleep(K_SECONDS(5));
	/* Send data */
	wifi_send_data();
#else
	/* Program channel in IDLE mode */
	wifi_set_channel();

	/* Send data */
	wifi_send_data();
#endif

	return 0;
}
