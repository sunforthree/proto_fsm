from scapy.utils import rdpcap
from Pstate import State, Rule, Parser, Action
from scapy.all import rdpcap
from scapy2dict import to_dict
from fsm_file_generator import json_switch_dict

# deal with the rule and generate MatchObj
def rule_to_Parser(rule_dict={}):
    return Parser(rule_dict['name'], rule_dict['match_dict'])

class Machine:
    def __init__(self):
        pass

    def info(self):
        pass

    def fsm(self, fsm_dict={}, packet_list=[]):
        print("This fsm is used to parsering %s." % (fsm_dict['name']))

        # Create state classes and add them to a set.
        states = []
        fsm_states = fsm_dict['states']
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
            state_Obj = State(name, rule_Obj, action_Obj)
            states.append(state_Obj)

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
                This means this fsm is not support dynamic processing, it's still a test version.
                When you give packets to it, the corrects packets must in the set, or you can't get the final answer.
                TODO A dynamic version, can listen packets which come from Machineset.
            '''
            
            # None use here, a error logic.
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
                            So write a exception
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
                            add_match_dict things be like: {S1.src: xxx.xxx.x.x} 
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
                    break

            exe_packet_number += 1


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
    # Read packets and change them to dict
    packets = rdpcap('dns_http.pcapng')
    packet_list = []
    for packet in packets:
        packet_list.append(to_dict(packet))

    # Read the json file(test here, just use dns_http)
    json_name = 'dns_http'
    fsm_dict = json_switch_dict(json_name)
    test_fsm = Machine()
    test_fsm.fsm(fsm_dict, packet_list)