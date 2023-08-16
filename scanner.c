#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdlib.h>
#include <string.h>

#define ARP_TABLE_SIZE 100
#define DNS_TABLE_SIZE 100

enum PacketType
{
    ARP_PACKET,
    DNS_PACKET,
    UNKNOWN_PACKET
};

struct arp_cache_entry
{
    struct in_addr ip_addr;
    struct ether_addr mac_addr;
    struct arp_cache_entry *next;
};

struct dns_request
{
    struct in_addr ip_addr;
    struct ether_addr mac_addr;
};

struct dns_response
{
    struct in_addr request_ip_addr;
    struct in_addr response_ip_addr;
};

struct dns_table
{
    struct arp_cache_entry *arp_cache[ARP_TABLE_SIZE];
    struct dns_request dns_requests[DNS_TABLE_SIZE];
    struct dns_response dns_responses[DNS_TABLE_SIZE];
};

struct dns_table dns_table;

int hash_index(const struct in_addr ip_addr)
{
    return ntohl(ip_addr.s_addr) % ARP_TABLE_SIZE;
}

void insert_arp_entry(struct in_addr ip_addr, struct ether_addr mac_addr)
{
    int index = hash_index(ip_addr);
    struct arp_cache_entry *entry = (struct arp_cache_entry *)malloc(sizeof(struct arp_cache_entry));
    entry->ip_addr = ip_addr;
    entry->mac_addr = mac_addr;
    entry->next = dns_table.arp_cache[index];
    dns_table.arp_cache[index] = entry;
}

struct ether_addr *lookup_arp_entry(struct in_addr ip_addr)
{
    int index = hash_index(ip_addr);
    struct arp_cache_entry *entry = dns_table.arp_cache[index];
    while (entry != NULL)
    {
        if (entry->ip_addr.s_addr == ip_addr.s_addr)
        {
            return &(entry->mac_addr);
        }
        entry = entry->next;
    }
    return NULL;
}

void insert_dns_request(struct in_addr ip_addr, struct ether_addr mac_addr)
{
    int hash_index_val = hash_index(ip_addr);
    dns_table.dns_requests[hash_index_val].ip_addr = ip_addr;
    dns_table.dns_requests[hash_index_val].mac_addr = mac_addr;
}

struct ether_addr *lookup_dns_request(struct in_addr ip_addr)
{
    int hash_index_val = hash_index(ip_addr);
    if (dns_table.dns_requests[hash_index_val].ip_addr.s_addr == ip_addr.s_addr)
    {
        return &(dns_table.dns_requests[hash_index_val].mac_addr);
    }
    return NULL;
}

void insert_dns_response(struct in_addr request_ip_addr, struct in_addr response_ip_addr)
{
    int hash_index_val = hash_index(request_ip_addr);
    dns_table.dns_responses[hash_index_val].request_ip_addr = request_ip_addr;
    dns_table.dns_responses[hash_index_val].response_ip_addr = response_ip_addr;
}

struct in_addr *lookup_dns_response(struct in_addr request_ip_addr)
{
    int hash_index_val = hash_index(request_ip_addr);
    if (dns_table.dns_responses[hash_index_val].request_ip_addr.s_addr == request_ip_addr.s_addr)
    {
        return &(dns_table.dns_responses[hash_index_val].response_ip_addr);
    }
    return NULL;
}

enum PacketType classify_packet(const struct ether_header *eth_hdr)
{
    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP)
    {
        return ARP_PACKET;
    }
    else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
    {
        const struct ip *ip_hdr = (const struct ip *)(eth_hdr + 1);
        if (ip_hdr->ip_p == IPPROTO_UDP)
        {
            const struct udphdr *udp_hdr = (const struct udphdr *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);
            if (ntohs(udp_hdr->uh_dport) == 53)
            {
                return DNS_PACKET;
            }
        }
    }
    return UNKNOWN_PACKET;
}

void process_packet(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    struct ether_header *eth_hdr = (struct ether_header *)packet;
    enum PacketType packet_type = classify_packet(eth_hdr);

    switch (packet_type)
    {
        case ARP_PACKET:
        {
            const struct ether_arp *arp_hdr = (const struct ether_arp *)(eth_hdr + 1);
            struct in_addr ip_addr;
            struct ether_addr mac_addr;

            memcpy(&ip_addr, arp_hdr->arp_spa, sizeof(struct in_addr));
            memcpy(&mac_addr, arp_hdr->arp_sha, sizeof(struct ether_addr));

            struct ether_addr *cached_mac_addr = lookup_arp_entry(ip_addr);
            if (cached_mac_addr && memcmp(cached_mac_addr, &mac_addr, sizeof(struct ether_addr)) != 0)
            {
                printf("ARP poisoning detected from %s\n", inet_ntoa(ip_addr));
            }

            insert_arp_entry(ip_addr, mac_addr);

            break;
        }
        case DNS_PACKET:
        {
            const struct ip *ip_hdr = (const struct ip *)(eth_hdr + 1);
            const struct udphdr *udp_hdr = (const struct udphdr *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);
            const u_char *dns_data = (const u_char *)udp_hdr + sizeof(struct udphdr);

            if ((dns_data[2] & 0x80) == 0x80)
            {
                struct in_addr request_ip_addr;
                memcpy(&request_ip_addr, dns_data + 12, sizeof(struct in_addr));
                struct in_addr *cached_response_ip = lookup_dns_response(request_ip_addr);
                struct in_addr response_ip_addr;
                memcpy(&response_ip_addr, dns_data + 12 + sizeof(struct in_addr), sizeof(struct in_addr));

                if (cached_response_ip && cached_response_ip->s_addr != response_ip_addr.s_addr)
                {
                    printf("DNS Spoofing detected from %s\n", inet_ntoa(request_ip_addr));
                }
                else
                {
                    insert_dns_response(request_ip_addr, response_ip_addr);
                }
            }
            else
            {
                struct in_addr dns_request_ip_addr;
                memcpy(&dns_request_ip_addr, dns_data + 12, sizeof(struct in_addr));
                struct ether_addr *cached_mac_addr = lookup_dns_request(dns_request_ip_addr);
                if (cached_mac_addr)
                {
                    insert_dns_request(dns_request_ip_addr, *cached_mac_addr);
                }
            }
            break;
        }
        case UNKNOWN_PACKET:
            break;
    }
}

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pcap_if_t *alldevs, *dev;

    memset(&dns_table, 0, sizeof(struct dns_table));

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        printf("[error] unable to find available network interfaces: %s\n", errbuf);
        return 1;
    }

    int interface_count = 0;
    printf("Available network interfaces:\n");
    for (dev = alldevs; dev; dev = dev->next)
    {
        printf("(%d) - %s\n", ++interface_count, dev->name);
    }

    int selected_interface;
    printf("Enter the number of the interface you want to use: ");
    scanf("%d", &selected_interface);

    int i = 1;
    for (dev = alldevs; dev; dev = dev->next)
    {
        if (i == selected_interface)
        {
            break;
        }
        i++;
    }

    if (!dev)
    {
        printf("[error] Invalid interface selection.\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        printf("[error] Unable to open PCAP: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    pcap_freealldevs(alldevs);

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "arp or udp port 53", 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        fprintf(stderr, "[error] Unable to compile filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "[error] Unable to set filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    pcap_loop(handle, 0, (pcap_handler)process_packet, NULL);

    for (int i = 0; i < ARP_TABLE_SIZE; i++)
    {
        struct arp_cache_entry *entry = dns_table.arp_cache[i];
        while (entry != NULL)
        {
            struct arp_cache_entry *next_entry = entry->next;
            free(entry);
            entry = next_entry;
        }
    }

    pcap_close(handle);
    return 0;
}
