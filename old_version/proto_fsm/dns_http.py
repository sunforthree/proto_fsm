from scapy import packet
from proto_fsm.Machine import State, Transition, Rule, Parser, Action
from scapy.all import IP, ls, UDP, DNS, DNSQR, sr1
from scapy2dict import to_dict

# just a fake class, not defined yet.
from packet_generator import Packet

states_names = ['S0', 'S1', 'S2']

# Create Parser.
match_ip_S0_to_S1 = {'proto': 17}
pars_ip_S0_to_S1 = Parser('IP', match_ip_S0_to_S1)
match_udp_S0_to_S1 = {'sport': 53, 'dport': 53}
pars_udp_S0_to_S1 = Parser('UDP', match_udp_S0_to_S1)
match_dns_S0_to_S1 = {'qr': 0}
pars_dns_S0_to_S1 = Parser('DNS', match_dns_S0_to_S1)

parser_S0_to_S1 = [pars_ip_S0_to_S1, pars_udp_S0_to_S1, pars_dns_S0_to_S1]

match_ip_S1_to_S2 = {'proto': 17}
pars_ip_S1_to_S2 = Parser('IP', match_ip_S1_to_S2)
match_udp_S1_to_S2 = {'sport': 53, 'dport': 53}
pars_udp_S1_to_S2 = Parser('UDP', match_udp_S1_to_S2)
match_dns_S1_to_S2 = {'qr': 1}
pars_dns_S1_to_S2 = Parser('DNS', match_dns_S1_to_S2)

parser_S1_to_S2 = [pars_ip_S1_to_S2, pars_udp_S1_to_S2, pars_dns_S1_to_S2]

# Create rule
rule_S0_to_S1 = Rule(parser_S0_to_S1)
rule_S1_to_S2 = Rule(parser_S1_to_S2)

# Create actions
# the first param in action_list_general is the chainmap's dict_name.
action_list_general = ['IP', ['src', 'dst'], 'UDP', [], 'DNS', ['qr']]
action_S0_to_S1 = Action(action_list_general)
action_S1_to_S2 = Action(action_list_general)

# Create transitions.
trans_S0_to_S1 = Transition(rule_S0_to_S1, action_S0_to_S1)
trans_S1_to_S2 = Transition(rule_S1_to_S2, action_S1_to_S2)
# the set of trans.
transitions = [trans_S0_to_S1, trans_S1_to_S2]

# Create state classes and add them to a set.
states = []
for i in range(0, len(states_names)):
    locals()[str(i) + states_names[i]] = State(states_names[i])
    states.append(locals()[str(i) + states_names[i]])



### Some code to execute states and transitions.(generally)
end_flag = True
exe_state_number = 0
exe_transition_number = 0

# Craft a DNS request and capture the returned DNS response.
dns_req = IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname='www.baidu.com'))
answer = sr1(dns_req, verbose=0)
dns_req_dict = to_dict(dns_req)
answer_dict = to_dict(answer)

packet_list = []
packet_list.append(dns_req_dict)
packet_list.append(answer_dict)

exe_packet_number = 0

while end_flag:
    if (exe_transition_number == len(transitions) - 1) and (exe_packet_number == len(packet_list) - 1):
        print('所有包都已经检查完啦！匹配成功，再见！')
        break
    now_state = states[exe_state_number]
    now_transition = transitions[exe_transition_number]
    # get a packet
    exe_packet = packet_list[exe_packet_number]
    print("Now state is ", now_state.get_name())
    now_parser_number = 0
    now_Rule = now_transition.get_Rule()
    for parser in now_Rule.get_rule_list():
        # get a parser which need to match
        paser_match_dict = parser.get_match_dict()
        print(paser_match_dict)
        paser_layer_name = parser.get_layer()
        print(paser_layer_name)
        for key in paser_match_dict.keys():
            if paser_match_dict[key] == exe_packet.get(paser_layer_name)[key]:
                print(key + str(exe_packet.get(paser_layer_name)[key]))
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