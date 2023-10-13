/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/** @file
 * @brief WiFi shell sample main function
 */
/* vivek */
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(shell, CONFIG_LOG_DEFAULT_LEVEL);
/* vivek */

#include <zephyr/sys/printk.h>
#include <zephyr/kernel.h>
#if defined(CLOCK_FEATURE_HFCLK_DIVIDE_PRESENT) || NRF_CLOCK_HAS_HFCLK192M
#include <nrfx_clock.h>
#endif
#include <zephyr/device.h>
#include <zephyr/net/net_config.h>
/* vivek */
#include <zephyr/net/ethernet.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/ethernet_mgmt.h>

#include "net_private.h"

#define CONFIG_WIFI_MAC_ADDRESS "F6:CE:36:00:00:01"

/* vivek */

#ifdef CONFIG_SLIP
/* Fixed address as the static IP given from Kconfig will be
 * applied to Wi-Fi interface.
 */
#define CONFIG_NET_CONFIG_SLIP_IPV4_ADDR "192.0.2.1"
#define CONFIG_NET_CONFIG_SLIP_IPV4_MASK "255.255.255.0"
#endif /* CONFIG_SLIP */

#ifdef CONFIG_USB_DEVICE_STACK
#include <zephyr/usb/usb_device.h>

/* Fixed address as the static IP given from Kconfig will be
 * applied to Wi-Fi interface.
 */
#define CONFIG_NET_CONFIG_USB_IPV4_ADDR "192.0.2.1"
#define CONFIG_NET_CONFIG_USB_IPV4_MASK "255.255.255.0"

int init_usb(void)
{
	int ret;

	ret = usb_enable(NULL);
	if (ret != 0) {
		printk("Cannot enable USB (%d)", ret);
		return ret;
	}

	return 0;
}
#endif

/* vivek */
#define RECV_BUFFER_SIZE 1000
#define STACK_SIZE 1024
#define WIFI_MAC_ADDR_LEN 6

/**
 * @brief Structure to hold raw packet information and data.
 *
 */
struct wifi_nrf_fmac_rawpkt_info {
        /** Magic number to distinguish packet is raw packet */
        unsigned int magic_number;
        /** Data rate of the packet */
        unsigned short data_rate;
        /** Packet length */
        unsigned short packet_length;
        /** Mode describing if packet is VHT, HT, HE or Legacy */
        unsigned char tx_mode;
        /** Wi-Fi access category mapping for packet */
        unsigned char queue;
	/** reserved char variable for driver */
	unsigned char reserved;
};

unsigned char lorem_ipsum_01[] =
        "vivek performed socket send"
        "\n";

struct packet_data {
        int send_sock;
        int recv_sock;
        char recv_buffer[RECV_BUFFER_SIZE];
};
/* vivek */

int main(void)
{
/* vivek */
#if 0
	int ret;
	struct net_if *iface;
        struct packet_data pkt;
        struct sockaddr_ll dst = { 0 };
	unsigned char *buffer;
	size_t length;
	struct wifi_nrf_fmac_rawpkt_info pkt_info;
#endif	
/* vivek */ 

#if defined(CLOCK_FEATURE_HFCLK_DIVIDE_PRESENT) || NRF_CLOCK_HAS_HFCLK192M
	/* For now hardcode to 128MHz */
	nrfx_clock_divider_set(NRF_CLOCK_DOMAIN_HFCLK,
			       NRF_CLOCK_HFCLK_DIV_1);
#endif
	printk("Starting %s with CPU frequency: %d MHz\n", CONFIG_BOARD, SystemCoreClock/MHZ(1));
#if 0
        iface = net_if_get_first_wifi();
	struct net_linkaddr *linkaddr = net_if_get_link_addr(iface);

        printk("iface->if_dev->operational_state = %d\n", iface->if_dev->oper_state);

        pkt.send_sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
        if (pkt.send_sock < 0) {
                printk("Failed to create raw socket : %d\n", errno);
                return -errno;	
        } else {
                printk("raw socket created \n");
        }

        dst.sll_ifindex = net_if_get_by_iface(net_if_get_first_wifi());
	dst.sll_halen = WIFI_MAC_ADDR_LEN;
	memcpy(dst.sll_addr, linkaddr->addr, WIFI_MAC_ADDR_LEN);

	printk("%x:%x:%x:%x:%x:%x\n", dst.sll_addr[0], dst.sll_addr[1], dst.sll_addr[2], dst.sll_addr[3], dst.sll_addr[4], dst.sll_addr[5]);
        printk("the ifindex of the device after net_if_get_first_wifi is %d\n", dst.sll_ifindex);
        printk("the new code is here\n");
        
	dst.sll_family = AF_PACKET;

        ret = bind(pkt.send_sock, (const struct sockaddr *)&dst,
                   sizeof(struct sockaddr_ll));
        if (ret < 0) {
                printk("Failed to bind packet socket : %d\n", errno);
                return -errno;
        } else {
                printk("bind packet successful\n");
        }

	buffer = (unsigned char *)malloc(sizeof(struct wifi_nrf_fmac_rawpkt_info) + sizeof(lorem_ipsum));
	length = sizeof(struct wifi_nrf_fmac_rawpkt_info) + sizeof(lorem_ipsum);
	
	pkt_info.magic_number = 0x12345678;
	pkt_info.data_rate = 9;
	pkt_info.packet_length = sizeof(lorem_ipsum);
	pkt_info.queue = 1;

        printk("length of loremipsum is %d\n", sizeof(lorem_ipsum));
	printk("length of struct is %d\n", sizeof(struct wifi_nrf_fmac_rawpkt_info));
        printk("total length is %d\n", length);
	
	memcpy(buffer, &pkt_info, sizeof(struct wifi_nrf_fmac_rawpkt_info));
	memcpy((buffer+sizeof(struct wifi_nrf_fmac_rawpkt_info)), lorem_ipsum, sizeof(lorem_ipsum));
        
	/* Sending dummy data */
        ret = sendto(pkt.send_sock, buffer, length, 0,
                             (const struct sockaddr *)&dst,
                             sizeof(struct sockaddr_ll));

        if (ret < 0) {
                printk("Failed to send, errno %d\n", errno);
        } else {
                printk("send successful\n");
        }

        (void)close(pkt.send_sock);
        printk("socket closed \n");
#endif
	return 0;
}
