'''
    Test file: MachineSet
'''
import sys
sys.path.append(".")
from MachineSet import MachineSet
from scapy.utils import rdpcap
from scapy2dict import to_dict
from pyinstrument import Profiler


if __name__ == '__main__':
    profiler = Profiler()
    profiler.start()

    # Read packets and change them to dict
    packets = rdpcap('dns_http.pcapng')
    packet_list = []
    for packet in packets:
        packet_list.append(to_dict(packet))
    
    ms = MachineSet()

    profiler.stop()
    profiler.print()