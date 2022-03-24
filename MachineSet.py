# This file use to define the set of fsm and recieve event.
from pickle import PROTO
from platform import machine
from Event import Event
from Machine import Machine
from pyinstrument import Profiler
from fsm_file_generator import json_switch_dict

# Test import here.
from scapy.all import rdpcap
from scapy2dict import to_dict
from global_variable import *
class MachineSet:

    def __init__(self):
        print("A new MachineSet has been defined.")
        # save machines
        # eg: 'DNS-HTTP': listobj
        '''
            __machine_dict:
                (private)This dict is used to save machines.
                And these machines are organized as listobj.
                eg: 'DNS-HTTP': listobj
            __fsm_dict:
                (private)This dict is used to save fsm_dict,
                which is the parameter of the creation of machine.
                Save all fsm_dict here helps add/delete rules in the fsm_dict,
                and update to the machine.
                eg: 'DNS-HTTP': dictobj(rule, action, goto in)
        '''
        self.__machine_dict = dict()
        self.__fsm_dict = dict()


    def check_machine_set(self, machine_name: str()):
        if machine_name in self.__machine_dict.keys():
            return True
        else:
            return False

    def new_machine_set(self, machine_name: str()):
        # 新建一个machine_set的时候，自动新建一个自动机并添加
        self.__machine_dict[machine_name] = list()
        self.__fsm_dict[machine_name] = json_switch_dict(machine_name)
        new_machine = Machine(self.__fsm_dict[machine_name])
        self.__machine_dict[machine_name].append(new_machine)

    def check_packet(self, packet):
        # Check if the machine can parse the protocol which the packet has.
        for key in packet.keys():
            if key in PROTOCOL.keys():
                return key
        
        return False

    def check_packets(self, packet_list: list()):
        # Check application protocol
        for packet in packet_list:
            # Check if the machine can parse the protocol
            parse_protocol = self.check_packet(packet)
            if parse_protocol != False:
                # Check if there has this kind machine-set.
                if self.check_machine_set(PROTOCOL[parse_protocol]):
                    self.send_packet(packet, parse_protocol)
                # Don't have the kind machine-set, new one.
                else:
                    self.new_machine_set(PROTOCOL[parse_protocol])
                    self.send_packet(packet, parse_protocol)

    def send_packet(self, packet, parse_protocol):
        # 首先与列表中尚未解析完成的自动机进行匹配，如果与这些自动机需要的包相同，则送入
        # 此处是给队列中每一个需要该包的自动机均送入，因此该send方法为单向
        # 同时在队列中检查到自动机已解析完成，即pack_flag == ''，则将该自动机从队列中剔除
        new_flag = True
        for machine in self.__machine_dict[PROTOCOL[parse_protocol]]:
            if parse_protocol == machine.get_pack_flag():
                new_flag = False
                machine.state_processing(packet)
            elif machine.get_pack_flag() == '':
                new_flag = False
                self.__machine_dict[PROTOCOL[parse_protocol]].remove(machine)

                '''
                    这一块的代码存疑，添不添加该段，效果一样，需要DEBUG验证
                    Time: 2022-03-23
                    TODO: DEBUG
                '''        
                # 如果此时该自动机队列中没有自动机，则新建一个，保证之后来的包可以正常解析
                if self.__machine_dict[PROTOCOL[parse_protocol]] == []:
                    new_machine = Machine(self.__fsm_dict[PROTOCOL[parse_protocol]])
                    self.__machine_dict[PROTOCOL[parse_protocol]].append(new_machine)
        
        
        # 如果该包为该队列自动机需要的第一个包，且已存在的自动机没有需要该包的，
        # 则新增一个自动机用来解析该包
        if new_flag and parse_protocol == self.__machine_dict[PROTOCOL[parse_protocol]][0].get_first_pack_flag():
            new_machine = Machine(self.__fsm_dict[PROTOCOL[parse_protocol]])
            new_machine.state_processing(packet)
            self.__machine_dict[PROTOCOL[parse_protocol]].append(new_machine)

    def add_rule(self, fsm_dict={}):
        pass

if __name__ == '__main__':
    profiler = Profiler()
    profiler.start()

    ms = MachineSet()

    # Read packets and change them to dict
    packets = rdpcap('dns_http.pcapng')
    packet_list = []
    for packet in packets:
        packet_list.append(to_dict(packet, True))

    ms.check_packets(packet_list)

    # print(MAP_TABLE)

    profiler.stop()
    profiler.print()