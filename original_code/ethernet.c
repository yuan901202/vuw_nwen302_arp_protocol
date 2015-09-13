/*
 * ethernet.c
 *
 * David C. Harrison (davidh@ecs.vuw.ac.nz) September 2014
 *
 * Simplistic Ethernet data-link layer for cnet v3.2.4, tightly coupled to the
 * associated IP network layer and the cnet physical layer.
 *
 * Note: You will need to modify this file to connect back to your fully
 * functional ARP implementation.
 *
 */

#include <string.h>
#include <stdio.h>
#include <stdio.h>
#include "ethernet.h"
#include "ip.h"
#include "arp.h"

typedef struct {
    CnetNICaddr        destination;
    CnetNICaddr        source;
    unsigned short     type;
} EthernetHeader;

#define ETHERNET_HEADER_SIZE sizeof(EthernetHeader)

#define MINIMUM_ETHERNET_PACKET_SIZE     64 // bytes

static int mac_addresses_match(CnetNICaddr left, CnetNICaddr right)
{
    for (int i = 0 ; i < LEN_NICADDR; i++) {
        if (left[i] != right[i])
            return false;
    }
    return true;
}

static int packet_is_for_this_node(EthernetHeader *header)
{
    return mac_addresses_match(header->destination, linkinfo[1].nicaddr) ||
        mac_addresses_match(header->destination, NICADDR_BCAST);
}

static void physical_ready(CnetEvent ev, CnetTimerID timer, CnetData data)
{
    int link = 1;
    size_t length;
    char packet[MAX_MESSAGE_SIZE];
    CHECK(CNET_read_physical(&link, packet, &length));
    EthernetHeader *header = (EthernetHeader *) packet;

    if (!packet_is_for_this_node(header))
        return;

    switch (header->type) {
        case ETHERTYPE_IP:
            ip_accept(packet + ETHERNET_HEADER_SIZE, length - ETHERNET_HEADER_SIZE);
            break;
        case ETHERTYPE_ARP:
            fprintf(stderr, "WHOOPS! Looks like you haven't handled ARP packets yet :)\n");
            break;
        default:
            fprintf(stderr, "Unknown Ethernet packet type: %u\n", header->type);
    }
}

int ethernet_send(CnetNICaddr to, unsigned short type, char *payload, size_t length)
{
    EthernetHeader header;
    memcpy(header.destination, to, LEN_NICADDR);
    memcpy(header.source, linkinfo[1].nicaddr, LEN_NICADDR);
    header.type = type;

    size_t len = length + ETHERNET_HEADER_SIZE;
    len = len < MINIMUM_ETHERNET_PACKET_SIZE ? MINIMUM_ETHERNET_PACKET_SIZE : len;

    char packet[len];
    memcpy(packet, (char *) &header, ETHERNET_HEADER_SIZE);
    memcpy(packet + ETHERNET_HEADER_SIZE, payload, length);

    return CNET_write_physical(1, (char *) &packet, &len);
}

void ethernet_init()
{
    CNET_set_handler(EV_PHYSICALREADY, physical_ready, 0);
}
