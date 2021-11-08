from scapy import packet
from Machine import State, Transition, Rule, MatchObj, Action
from scapy.all import IP, ls, UDP, DNS, DNSQR, sr1
from scapy2dict import to_dict
from fsm_file_generator import json_switch_dict

# just a fake class, not defined yet.
from packet_generator import Packet

# deal with the rule and generate MatchObj
def rule_to_MatchObj(rule_dict={}):
    return MatchObj(rule_dict['name'], rule_dict['match_dict'])

def generate_Transition(rule=Rule, action=Action):
    return Transition(rule, action)

# the most important func here.
def fsm(fsm_dict={}, packet_list=[]):
    print("This fsm is used to parsering %s." % (fsm_dict['name']))

    # Create state classes and add them to a set.
    states = []
    for i in range(0, len(fsm_dict['states_names'])):
        locals()[str(i) + fsm_dict['states_names'][i]] = State(fsm_dict['states_names'][i])
        states.append(locals()[str(i) + fsm_dict['states_names'][i]])

    print("The fsm will begin with %s." % (fsm_dict['head']))

    # Create transitions.
    transitions = []
    fsm_dict_trans = fsm_dict['transitions']
    for tran_key in fsm_dict_trans.keys():
        MatchObj_list = []
        # tran_value include rule and action.
        tran_value = fsm_dict_trans[tran_key]
        # get rule and action steply.
        # First is rule list.
        # Second is action list
        for second_key in tran_value.keys():
            second_value = tran_value[second_key]
            # deal with rule
            if second_key.startswith('rule'):
                for rule_dict in second_value:
                    MatchObj_list.append(rule_to_MatchObj(rule_dict))
                rule_Obj = Rule(MatchObj_list)
            # deal with action
            elif second_key.startswith('action'):
                action_Obj = Action(second_value)
        transitions.append(generate_Transition(rule_Obj, action_Obj))
    
    #deal with packet

    ### Some code to execute states and transitions.(generally)
    end_flag = True
    exe_state_number = 0
    exe_transition_number = 0
    exe_packet_number = 0

    while end_flag:
        if (exe_state_number == len(states) - 1):
            print("Now state is %s and it's the last state" % (now_state.get_name()))
            print('所有包都已经检查完啦！匹配成功，再见！')
            break
        now_state = states[exe_state_number]
        now_transition = transitions[exe_transition_number]
        # get a packet
        exe_packet = packet_list[exe_packet_number]
        print("Now state is ", now_state.get_name())
        now_MatchObj_number = 0
        now_Rule = now_transition.get_Rule()
        for MatchObj in now_Rule.get_rule_list():
            # get a MatchObj which need to match
            paser_match_dict = MatchObj.get_match_dict()
            paser_layer_name = MatchObj.get_layer()
            for key in paser_match_dict.keys():
                if paser_match_dict[key] == exe_packet.get(paser_layer_name)[key]:
                    continue
                else:
                    # if not true, exit.
                    end_flag = False
                    break
        
        # if this transition match OK, do action.
        action = now_transition.get_Action()
        action.ok()
        exe_state_number += 1
        exe_transition_number += 1
        exe_packet_number += 1 

    return 0

# Craft a DNS request and capture the returned DNS response.
dns_req = IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname='www.thepacketgeek.com'))
answer = sr1(dns_req, verbose=0)
dns_req_dict = to_dict(dns_req)
answer_dict = to_dict(answer)

packet_list = []
packet_list.append(dns_req_dict)
packet_list.append(answer_dict)

# test here.
json_name = 'dns-http'
fsm_dict = json_switch_dict(json_name)
fsm(fsm_dict, packet_list)