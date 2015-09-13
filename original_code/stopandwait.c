/*
 * stopandwait.c
 *
 * David C. Harrison (davidh@ecs.vuw.ac.nz) September 2014
 *
 * This is a Modified version of the cnet v3.2.4 provided stop-and-wait
 * protocol, used here at the transport layer. This implementation supports
 * more than two hosts, all of whch send and receive data simultaneously.
 *
 * Pertinent sections of the original author's comments are:
 *
 * *************************************************************************
 *
 *  This is an implementation of a stop-and-wait data link protocol.
 *  It is based on Tanenbaum's `protocol 4', 2nd edition, p227
 *  (or his 3rd edition, p205).
 *  This protocol employs only data and acknowledgement frames -
 *  piggybacking and negative acknowledgements are not used.
 *
 * *************************************************************************
 *
 */

#include <cnet.h>
#include <stdlib.h>
#include <string.h>
#include "ip.h"

typedef enum    { DL_DATA, DL_ACK }   PacketType;

typedef struct {
    PacketType  type;          // only ever DL_DATA or DL_ACK
    size_t         len;           // the length of the payload field only
    int         checksum;      // checksum of the whole frame
    int         seq;           // only ever 0 or 1
    CnetAddr    source;
    CnetAddr    destination;
} StopAndWaitHeader;

typedef struct {
    CnetAddr    destaddr;
    char        payload[MAX_MESSAGE_SIZE];
    size_t        length;
    CnetTimerID    timer;
    int         ackexpected;
    int            frameexpected;
    int            nextframetosend;
} LastPacket;

#define STOPANDWAIT_HEADER_SIZE  sizeof(StopAndWaitHeader)

static char ACK_MSG[MAX_MESSAGE_SIZE];
static CnetTime ACK_TIMEOUT = 1 * 1000 * 1000; // One second in micro seconds

#define MAX_HOSTS 254
#define FIRST_TIMER 1000

static LastPacket *lastPacketsByDestAddr[MAX_HOSTS];
static LastPacket *lastPacketsByTimerID[MAX_HOSTS];

static void setLastPacketByTimerId(LastPacket *lastPacket, CnetTimerID timer)
{
    lastPacketsByTimerID[(timer - FIRST_TIMER) % MAX_HOSTS] = lastPacket;
}

static LastPacket *getLastPacketByTimerId(CnetTimerID timer)
{
    return lastPacketsByTimerID[(timer - FIRST_TIMER) % MAX_HOSTS];
}

static LastPacket *getLastPacketByDestAddr(CnetAddr destaddr)
{
    LastPacket *lastPacket = lastPacketsByDestAddr[(int)destaddr];
    if (lastPacket == NULL) {
        lastPacket = calloc(1, sizeof(LastPacket));
        lastPacket->frameexpected = 0;
        lastPacket->ackexpected = 0;
        lastPacket->nextframetosend = 0;
        lastPacket->length = 0;
        lastPacket->timer = NULLTIMER;
        lastPacketsByDestAddr[(int)destaddr] = lastPacket;
    }
    return lastPacket;
}

static void send_message(CnetAddr destaddr, PacketType type, char *payload, size_t length, int seqno)
{
    StopAndWaitHeader header;
    header.type = type;
    header.seq = seqno;
    header.checksum = 0;
    header.len = length;
    header.destination = destaddr;;
    header.source = nodeinfo.address;

    LastPacket *lastPacket = getLastPacketByDestAddr(destaddr);

    switch (type) {
        case DL_ACK:
            printf("ACK transmitted to %lu, seq=%d\n", header.destination, seqno);
            break;

        case DL_DATA: {
            lastPacket->timer = CNET_start_timer(EV_TIMER1, ACK_TIMEOUT, 0);
            setLastPacketByTimerId(lastPacket, lastPacket->timer);
            printf("DATA transmitted to %lu, seq=%d\n", header.destination, seqno);
            break;
        }
    }

    char packet[MAX_MESSAGE_SIZE];

    memcpy(packet, (char *) &header, STOPANDWAIT_HEADER_SIZE);
    memcpy(packet + STOPANDWAIT_HEADER_SIZE, payload, (int) length);
    header.checksum = CNET_ccitt((unsigned char *) packet, (int) length + STOPANDWAIT_HEADER_SIZE);
    memcpy(packet, (char *) &header, STOPANDWAIT_HEADER_SIZE);

    ip_send(destaddr, IPPROTO_STOP_AND_WAIT, packet, length + STOPANDWAIT_HEADER_SIZE);
}

static void on_application_ready(CnetEvent ev, CnetTimerID timer, CnetData data)
{
    size_t length;
    CnetAddr destaddr;
    char payload[MAX_MESSAGE_SIZE];
    CHECK(CNET_read_application(&destaddr, payload, &length));

    LastPacket *lastPacket = getLastPacketByDestAddr(destaddr);

    memcpy(lastPacket->payload, payload, length);
    lastPacket->length = length;
    lastPacket->destaddr = destaddr;

    CNET_disable_application(ALLNODES);

    send_message(destaddr, DL_DATA, payload, length, lastPacket->nextframetosend);
    lastPacket->nextframetosend = 1 - lastPacket->nextframetosend;
}

static void on_timer(CnetEvent ev, CnetTimerID timer, CnetData data)
{
    LastPacket *lastPacket = getLastPacketByTimerId(timer);
    printf("timeout, seq=%d, timer %d\n", lastPacket->ackexpected, timer);
    send_message(lastPacket->destaddr, DL_DATA, lastPacket->payload, lastPacket->length, lastPacket->ackexpected);
}

void stopandwait_accept(char *packet, size_t length)
{
    StopAndWaitHeader *header = (StopAndWaitHeader *) packet;
    int checksum = header->checksum;
    header->checksum  = 0;

    if(CNET_ccitt((unsigned char *)packet, (int)length) != checksum) {
        printf("\t\t\t\tBAD checksum - frame ignored\n");
        return;
    }

    LastPacket *lastPacket = getLastPacketByDestAddr(header->source);

    switch (header->type) {
        case DL_ACK:
            printf("\t\t\t\tACK received from %lu, seq=%d", header->source, header->seq);
            if (header->seq == lastPacket->ackexpected) {
                CNET_stop_timer(lastPacket->timer);
                lastPacket->ackexpected = 1 - lastPacket->ackexpected;
                CNET_enable_application(ALLNODES);
            }
            else {
                printf(", ignored");
            }
            printf("\n");
            break;

        case DL_DATA:
            printf("\t\t\t\tDATA received from %lu, seq=%d, ", header->source, header->seq);
            if (header->seq == lastPacket->frameexpected) {
                printf("up to application\n");
                //length = header->len;
                length -= STOPANDWAIT_HEADER_SIZE;
                CHECK(CNET_write_application(packet + STOPANDWAIT_HEADER_SIZE, &length));
                lastPacket->frameexpected = 1 - lastPacket->frameexpected;
            } else {
                printf("ignored\n");
            }

            send_message(header->source, DL_ACK, ACK_MSG, 32, header->seq);
            break;
    }
}

void reboot_node(CnetEvent ev, CnetTimerID timer, CnetData data)
{
    for (int i = 0; i < MAX_HOSTS; i++) {
        lastPacketsByDestAddr[i] = NULL;
    }

    CNET_set_handler(EV_APPLICATIONREADY, on_application_ready, 0);
    CNET_set_handler(EV_TIMER1,           on_timer, 0);

    ip_init();

    CNET_enable_application(ALLNODES);
}
