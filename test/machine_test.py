import sys
sys.path.append(".")
from Machine import Machine
from scapy.utils import rdpcap
from scapy2dict import to_dict
from fsm_file_generator import json_switch_dict
from pyinstrument import Profiler


if __name__ == '__main__':
    profiler = Profiler()
    profiler.start()


    # Read packets and change them to dict
    packets = rdpcap('dns_http.pcapng')
    packet_list = []
    for packet in packets:
        packet_list.append(to_dict(packet))

    test = Machine(json_switch_dict('dns_http'))

    for packet in packet_list:
        test.state_processing(packet)

    profiler.stop()
    profiler.print()