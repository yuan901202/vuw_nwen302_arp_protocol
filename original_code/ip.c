/*
 * ip.c
 *
 * David C. Harrison (davidh@ecs.vuw.ac.nz) September 2014
 *
 * Simplistic IPv4 network layer for cnet v3.2.4, tightly coupled to the
 * associated Ethernet data-link and StopAndWait transport layers.
 *
 */
#include <stdlib.h>
#include <string.h>
#include "arp.h"
#include "ethernet.h"
#include "stopandwait.h"

// Assumes little endian (Intel processor)
typedef struct {
    unsigned int   header_length;
    unsigned int   version;
    unsigned short type_of_service;
    unsigned short total_length;
    unsigned short id;
    unsigned short fragment_offset;
    unsigned char  time_to_live;
    unsigned char  protocol;
    unsigned short checksum;
    CnetAddr       source;
    CnetAddr       destination;
} IpHeader;

#define IP_HEADER_SIZE sizeof(IpHeader)

void ip_accept(char *packet, size_t length)
{
    IpHeader *header = (IpHeader *)packet;
    stopandwait_accept(
        packet + header->header_length,
        length - header->header_length);
}

void ip_send(CnetAddr to, unsigned char protocol, char *payload, size_t length)
{
    IpHeader header;
    header.header_length = IP_HEADER_SIZE;
    header.protocol = protocol;
    header.total_length = (unsigned short) (IP_HEADER_SIZE + length);
    header.source = nodeinfo.address;
    header.destination = to;

    char *packet = calloc(1, header.total_length);
    memcpy(packet, (char *) &header, IP_HEADER_SIZE);
    memcpy(packet + IP_HEADER_SIZE, payload, (int) length);

    CnetNICaddr destAddr;
    if (arp_get_mac_address(to, destAddr)) {
        ethernet_send(destAddr, ETHERTYPE_IP, packet, header.total_length);
    }
    free(packet);
}

void ip_init()
{
    ethernet_init();
}
