from os.path import abspath, dirname
import json

# switch the dict to the json file.
# write it in ./fsm_model
def dict_switch_json(fsm_dict={}):
    file_name = '{name}.{type}'
    file_name = abspath(dirname(__file__)) + "\\fsm_model\\" + file_name.format(name=fsm_dict['name'], type='json')

    jsObj = json.dumps(fsm_dict)
    fileObject = open(file_name, mode='w')
    fileObject.write(jsObj)
    fileObject.close()

# read the json file(localed in ./fsm_model) and switch it to dict.
def json_switch_dict(json_name=str):
    file_name = '{name}.{type}'
    file_name = abspath(dirname(__file__)) + "\\fsm_model\\" + file_name.format(name=json_name, type='json')
    with open(file_name) as json_file:
        return json.load(json_file)

# # example dns-http(just dns now)
# test_dict = {
#     'name': 'dns-http',
#     'states_names': ['S0', 'S1', 'S2'],
#     'head': 'S0',
#     'transitions': {

#         'trans_S0_to_S1': {
#             'rule_S0_to_S1': [
#                 {'name': 'IP', 'match_dict': {'proto': 17}},
#                 {'name': 'UDP', 'match_dict': {'sport': 53, 'dport': 53}},
#                 {'name': 'DNS', 'match_dict': {'qr': 0}}
#             ],

#             'action_S0_to_S1': [
#                 {'name': 'IP', 'action_dict': ['src', 'dst']}, 
#                 {'name': 'UDP', 'action_dict': []}, 
#                 {'name': 'DNS', 'action_dict': ['qr']}
#             ]
        
#         },

#         'trans_S1_to_S2': {
            
#             'rule_S1_to_S2': [
#                 {'name': 'IP', 'match_dict': {'proto': 17}},
#                 {'name': 'UDP', 'match_dict': {'sport': 53, 'dport': 53}},
#                 {'name': 'DNS', 'match_dict': {'qr': 1}}
#             ],

#             'action_S1_to_S2': [
#                 {'name': 'IP', 'action_dict': ['src', 'dst']}, 
#                 {'name': 'UDP', 'action_dict': []}, 
#                 {'name': 'DNS', 'action_dict': ['qr']}
#             ]
        
#         }

#     }
# }

# # example
# dict_switch_json(test_dict)