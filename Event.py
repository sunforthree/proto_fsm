# This file use to define the Event in proto_fsm
from scapy.all import ls

class Event:
    def __init__(self, pkt):
        print("A new Event has been defined.")
        self.pkt = pkt
    
    def Event_type(self):
        ls(self.pkt)

    # Get the string type of Event's pkt.
    def pkt_to_str(self):
        pkt_str = str(self.pkt)
        self.str = pkt_str
        return pkt_str

    
    