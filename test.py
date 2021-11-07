test_dict = {
    'name': 'dns-http',
    'states_names': ['S0', 'S1', 'S2'],
    'head': 'S0',
    'transitions': {

        'trans_S0_to_S1': {
            'rule_S0_to_S1': [
                {'name': 'IP', 'match_ip_S0_to_S1': {'proto': 17}},
                {'name': 'UDP', 'match_udp_S0_to_S1': {'sport': 53, 'dport': 53}},
                {'name': 'DNS', 'match_udp_S0_to_S1': {'qr': 0}}
            ],

            'action_S0_to_S1': ['IP', ['src', 'dst'], 'UDP', [], 'DNS', ['qr']]
        
        },

        'trans_S1_to_S2': {
            
            'rule_S1_to_S2': [
                {'name': 'IP', 'match_ip_S0_to_S1': {'proto': 17}},
                {'name': 'UDP', 'match_udp_S0_to_S1': {'sport': 53, 'dport': 53}},
                {'name': 'DNS', 'match_udp_S0_to_S1': {'qr': 1}}
            ],

            'action_S1_to_S2': ['IP', ['src', 'dst'], 'UDP', [], 'DNS', ['qr']]
        
        }

    }
}

print(test_dict['transitions'])