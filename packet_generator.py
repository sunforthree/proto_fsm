from scapy.arch.windows import show_interfaces
from scapy.sendrecv import sniff
from scapy.all import IP, ls, UDP, DNS, DNSQR, sr1
from Event import Event
from scapy2dict import to_dict


class Packet():
    def __init__(self, packet):
        self.packet = packet
    def get_packet(self):
        return self.packet

if __name__ == '__main__':
    pkt = IP(dst='192.168.1.2', ttl=10)
    event = Event(pkt)
    # event.Event_type()
    # print(event.pkt)
    # str = event.pkt_to_str()
    # print(str)

    # Craft a DNS request and capture the returned DNS response.
    dns_req = IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname='www.thepacketgeek.com'))
    answer = sr1(dns_req, verbose=0)

    ls(answer[IP])
    dns_req_dict = to_dict(dns_req)
    print(dns_req_dict)
    answer_dict = to_dict(answer)
    print(answer_dict.get('IP'))
