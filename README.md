# ARP Protocol
[NWEN302] Implement the ARP protocol with cnet

## What is ARP protocol?
ARP is used to resolve link layer addresses based on a apriori known network layer address; it is a critical function in multiple-access networks. The ARP protocol can be considered a method of routing within a MultiAccess single hop network segment such as Ethernet, Wifi, Zigbee etc. 

## What is cnet?
A network simulation environment cnet which has been developed for communication protocol analysis by UWA. And it will only run on Mac, Linux and BSD.

## How to running it?
$ cnet –g –O STOPANDWAIT

## Files changed:
- arp.c
   - add arp packet and arp table structure
   - handle arp packet and deal with arp table entry
- ethernet.c
   - forward Ethernet packet to my code
- ethernet.h
   - add Ethernet packet structure
- ip.c
   - add necessary method to deal with ip address
- ip.h
   - add prototypes
- stopandwait.c
   - add timeout method

## What this program can do?
Roughly speaking, your ARP component will need to do (at least) the following:

- Maintain some form of data structure mapping IP addresses to MAC addresses. This can be a simple or as sophisticated as you like but justify your choice of data structure in your report.
- When asked by IP for the MAC address corresponding to a supplied IP address, return it if you have it, or send an ARP-Request to find it. It is your choice whether you block waiting for the response or return immediately and force the transport layer to try again later. Whichever mode you choose, justify it in your report.
- Identify whether the ARP packets received from Ethernet are ARP-Requests or ARP-Responses.
- If required, send an ARP-Response. 

##  Requirements?
### Basic

- After a 30 second test, each node's ARP table should have a full list of all other node's MAC to IP address mappings.
- ARP request packets are not sent when an appropriate ARP entry already exists in the ARP table.
- Implement a standardised ARP packet header with correct values.
- The ARP table is updated on receiving an ARP request, not simply when receiving an ARP response. 

### Advanced

- ARP entries timeout.
- ARP table is of limited size (and less than the number of nodes in a given topology). 
