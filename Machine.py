from scapy.utils import rdpcap
from Pstate import State, Rule, Parser, Action
from scapy.all import rdpcap
from scapy2dict import to_dict
from fsm_file_generator import json_switch_dict
from DataToSql import DataToMysql
from pyinstrument import Profiler

# deal with the rule and generate MatchObj
def rule_to_Parser(rule_dict={}):
    return Parser(rule_dict['name'], rule_dict['match_dict'])

class Machine:

    def __init__(self, fsm_dict={}):
        '''
            extract_dict:
                This dict is used to save extract key-values in pcap.
                These key-values will used to generate readable sentence.
            format:
                This stringobj is used to output format string.
                The format type has writen in xx_xx.json
            name:
                Machine name, like 'DNS-HTTP'.
            pack_flag:
                Set to be the package's name which this machine need.
            first_pack_flag:
                The head state's pack_flag.
            __states:
                (private)Store states, listobj.
            __process_state:
                (private)The processing state, it initialized to the head.
        '''
        self.extract_dict = dict()
        self.format = fsm_dict['format']
        self.name = fsm_dict['name']
        self.pack_flag = str()
        self.first_pack_flag = str()
        self.__states = self.generate_states(fsm_dict['states'])
        self.__process_state = self.get_head_state(fsm_dict)
        self.add_match_dict = dict()

    def info(self):
        pass

    def get_pack_flag(self):
        return self.pack_flag

    def set_first_pack_flag(self, first_pack_flag):
        self.first_pack_flag = first_pack_flag

    def get_first_pack_flag(self):
        return self.first_pack_flag
        pass

    def generate_states(self, fsm_states: list) -> list:
        states = []

        '''
            state is s dictobj here.
            A state includes name, rule and action.
        '''

        for state in fsm_states:
            print('Create states.')
            Paser_list = []
            # get name, rule and action steply.
            for key in state.keys():
                value = state[key]
                # deal with name
                if key.startswith('name'):
                    name = value
                # deal with rule
                elif key.startswith('rule'):
                    for rule_dict in value:
                        Paser_list.append(rule_to_Parser(rule_dict))
                    rule_Obj = Rule(Paser_list)
                # deal with action
                elif key.startswith('action'):
                    action_Obj = Action(value['extract'], value['associate'])
                    action_Obj.set_goto(value['goto'])
                # deal with flag
                elif key.startswith('flag'):
                    flag = value
            state_Obj = State(name, rule_Obj, action_Obj)
            state_Obj.set_flag(flag)
            states.append(state_Obj)

        # self.__states = states
        return states

    def get_head_state(self, fsm_dict):
        head_state = fsm_dict['head']
        # find head state
        for state in self.__states:
            if state.get_name() == head_state:
                processing_state = state
                print('The fsm will begin with %s.' % processing_state.get_name())
        try:
            self.pack_flag = processing_state.get_flag()
            self.set_first_pack_flag(self.pack_flag)
            return processing_state
        except:
            print("invalid error")

    def state_processing(self, packet):
        '''
            This function used to process a state.
            It just only processes one state at one time,
            so call it multiple times can form a dynamic version.
            As the machine has initialized __process_state as the head,
            so the logic is process first and then find next.
        '''
        # get the current rule.
        process_rule = self.__process_state.get_Rule()
        Still_processing = True
        for parser in process_rule.get_rule_list():
                # get a parser which need to match
                parser_match_dict = parser.get_match_dict()
                parser_layer_name = parser.get_layer()
                '''
                    Matching key-value in packet and match_dict.
                    Notice:
                        parser_layer_name has two catalogues:
                            normal_layer: IP, UDP, DNS, HTTP...
                            Self_add: State(This means the key-values in it is comes from passed state.)
                '''
                # deal with normal layer
                if parser_layer_name != 'State':
                    # check exe_packet has the layer
                    if len(parser_match_dict.keys()) == 0:
                        try:
                            if len(packet.get(parser_layer_name)) != 0:
                                break
                        except:
                            Still_processing = False
                            break
                    for key in parser_match_dict.keys():
                        '''
                            Must consider if we get a packet and if don't have the layer we need
                            So we can write a exception
                        '''
                        try:
                            # if value has match, go on.
                            if parser_match_dict[key] == packet.get(parser_layer_name)[key]:
                                continue
                            # this state is not equal with this packet, break
                            else:
                                Still_processing = False
                                break
                        except:
                            Still_processing = False
                            break
                   
                # deal with Self_add(State)
                else:
                    # disassemble key
                    '''
                        eg: {'name': 'State', 'match_dict': {'IP.src': 'S1.dst', 'IP.dst': 'S1.src'}}
                        'IP.src' -> layer: IP, disa_key: src (for packet)
                        'S1.dst' for add_match_dict
                        disassemble key
                        eg: IP.dst -> layer: IP, disa_key: dst
                    '''
                    for key in parser_match_dict.keys():
                        # for packet
                        layer = key.split('.')[0]
                        disa_key = key.split('.')[1]
                        try:
                            # if value has match, go on.
                            if self.add_match_dict[parser_match_dict[key]] == packet.get(layer)[disa_key]:
                                continue
                            # this state is not equal with this packet, break
                            else:
                                Still_processing = False
                                break
                        except:
                            Still_processing = False
                            break
        # If a state matched, check if need to do action.
        if Still_processing:
            action = self.__process_state.get_Action()

            '''
                Deal with extract_dict.
                Date: 2022-02-25
                Change the list to dict and use it to generate format.
            '''
            for item in action.get_extract_dict():
                for ex_key in item['extract_list']:
                    field_name = '{state_name}.{key}'
                    field_name = field_name.format(state_name=self.__process_state.get_name(), key=ex_key)
                    self.extract_dict[field_name] = packet.get(item['layer'])[ex_key]

            # deal with associate
            if len(action.get_associate_list()) != 0:
                for item in action.get_associate_list():
                    '''
                        item be like: IP.src
                        add_match_dict things be like: {S0.src: xxx.xxx.x.x} 
                    '''
                    self.add_match_dict[self.__process_state.get_name() + '.' + item.split('.')[1]] = packet.get(item.split('.')[0])[item.split('.')[1]]

            # deal with goto
            if action.get_goto() != '':
                # find next state
                for state in self.__states:
                        if state.get_name() == action.get_goto():
                            self.__process_state = state
                            # update flag
                            self.pack_flag = self.__process_state.get_flag()
            # if goto == '', it means the fsm has goto the last state, stop.
            elif action.get_goto() == '':
                self.__process_state.get_Action().ok()
                self.extarct_processing()
                self.pack_flag = ''
                

    def fsm(self, fsm_dict={}, packet_list=[]):
        print("This fsm is used to parsering %s." % (fsm_dict['name']))
        self.name = fsm_dict['name']

        # Create state classes and add them to a list.
        fsm_states = fsm_dict['states']
        states = self.generate_states(fsm_states)
        
        # Deal with format.
        self.format = fsm_dict['format']

        '''
            Use some codes to execute states.(generally)
            add_match_dict:
                If Action has associate, the value in it will add in.
        '''
        end_flag = True
        exe_packet_number = 0
        add_match_dict = {}
        extract_list = []
        head_state = fsm_dict['head']
        # find head state
        for state in states:
            if state.get_name() == head_state:
                processing_state = state
                print('The fsm will begin with %s.' % processing_state.get_name())

        while end_flag:
            '''
                When to stop?
                If processing the last state in the states, the fsm will stop.
                It means this fsm is not support dynamic processing, it's still a test version.
                When you give packets to it, the corrects packets must in the set, or you couldn't get the final answer.
                TODO A dynamic version, can listen packets which come from Machineset.
            '''
            
            # None use here, an error logic.
            # if (exe_packet_number == len(packet_list) - 1):
            #         print("Now state is %s and packet is the last one." % (processing_state.get_name()))
            #         processing_state.get_Action().ok()
            #         break

            # get a packet
            exe_packet = packet_list[exe_packet_number]
            # get the current rule.
            processing_rule = processing_state.get_Rule()
            Still_processing = True
            for parser in processing_rule.get_rule_list():
                # get a parser which need to match
                parser_match_dict = parser.get_match_dict()
                parser_layer_name = parser.get_layer()
                '''
                    Matching key-value in packet and match_dict.
                    Notice:
                        parser_layer_name has two catalogues:
                            normal_layer: IP, UDP, DNS, HTTP...
                            Self_add: State(This means the key-values in it is comes from passed state.)
                '''
                # deal with normal layer
                if parser_layer_name != 'State':
                    # check exe_packet has the layer
                    if len(parser_match_dict.keys()) == 0:
                        try:
                            if len(exe_packet.get(parser_layer_name)) != 0:
                                break
                        except:
                            Still_processing = False
                            break
                    for key in parser_match_dict.keys():
                        '''
                            Must consider if we get a packet and if don't have the layer we need
                            So we can write a exception
                        '''
                        try:
                            # if value has match, go on.
                            if parser_match_dict[key] == exe_packet.get(parser_layer_name)[key]:
                                continue
                            # this state is not equal with this packet, break
                            else:
                                Still_processing = False
                                break
                        except:
                            Still_processing = False
                            break
                   
                # deal with Self_add(State)
                else:
                    # disassemble key
                    '''
                        eg: {'name': 'State', 'match_dict': {'IP.src': 'S1.dst', 'IP.dst': 'S1.src'}}
                        'IP.src' -> layer: IP, disa_key: src (for exe_packet)
                        'S1.dst' for add_match_dict
                        disassemble key
                        eg: IP.dst -> layer: IP, disa_key: dst
                    '''
                    for key in parser_match_dict.keys():
                        # for exe_packet
                        layer = key.split('.')[0]
                        disa_key = key.split('.')[1]
                        try:
                            # if value has match, go on.
                            if add_match_dict[parser_match_dict[key]] == exe_packet.get(layer)[disa_key]:
                                continue
                            # this state is not equal with this packet, break
                            else:
                                Still_processing = False
                                break
                        except:
                            Still_processing = False
                            break
            
            # If a state matched, check if need to do action.
            if Still_processing:
                action = processing_state.get_Action()

                '''
                    Deal with extract_dict.
                    Date: 2022-02-25
                    Change the list to dict and use it to generate format.
                '''
                for item in action.get_extract_dict():
                    for ex_key in item['extract_list']:
                        field_name = '{state_name}.{key}'
                        field_name = field_name.format(state_name=processing_state.get_name(), key=ex_key)
                        self.extract_dict[field_name] = exe_packet.get(item['layer'])[ex_key]
                # deal with extract_list
                '''
                    TODO 将extract_list提取，改为简单的可描述语言
                '''
                print(exe_packet_number)
                for item in action.get_extract_list():
                    for ex_key in item['extract_list']:
                        extract_list.append(exe_packet.get(item['layer'])[ex_key])
                
                # deal with associate
                if len(action.get_associate_list()) != 0:
                    for item in action.get_associate_list():
                        '''
                            item be like: IP.src
                            add_match_dict things be like: {S0.src: xxx.xxx.x.x} 
                        '''
                        add_match_dict[processing_state.get_name() + '.' + item.split('.')[1]] = exe_packet.get(item.split('.')[0])[item.split('.')[1]]

                # deal with goto
                if action.get_goto() != '':
                    # find next state
                    for state in states:
                            if state.get_name() == action.get_goto():
                                processing_state = state
                # if goto == '', it means the fsm has goto the last state, stop.
                elif action.get_goto() == '':
                    processing_state.get_Action().ok()
                    end_flag = False
                    
                    # test print here.
                    print(extract_list)
                    
                    break

            exe_packet_number += 1

    def extarct_processing(self):
        '''
            Time: 2022-02-24 22:17.
            TODO: change the key-values in it to sentence.
            Varible: self.format, self.extract_dict
            
        '''
        print(self.format % self.extract_dict)
        pass


'''
    test code here.
    TODO 2021/12/09
'''
if __name__ == '__main__':
    '''
        Library: Scapy
        Packet: dns_http.pcapng / dns_http_3packages.pcapng
        Model: dns_http.json (What's the differences between dns_http.json and dns-http.json>
                                dns_http.json is a new version without Transition.)
    '''
    
    profiler = Profiler()
    profiler.start()
    
    # Read packets and change them to dict
    packets = rdpcap('dns_http.pcapng')
    packet_list = []
    for packet in packets:
        packet_list.append(to_dict(packet, True))

    # Read the json file(test here, just use dns_http)
    json_name = 'dns_http'

    # '''
    #     Test S7_User_Data here.
    # '''
    # packets = rdpcap("test_s7.pcapng")
    # packet_list = []
    # for packet in packets:
    #     packet_list.append(to_dict(packet))
    # json_name = 'S7_User_Data'

    fsm_dict = json_switch_dict(json_name)
    test_fsm = Machine(fsm_dict)
    # test_fsm.info()
    test_fsm.fsm(fsm_dict, packet_list)
    test_fsm.extarct_processing()
    mysql = DataToMysql('root', 'ujG0yrpK3Z&0', 'fsm')
    mysql.write_dict(test_fsm.extract_dict, table_name=test_fsm.name)

    profiler.stop()
    profiler.print()