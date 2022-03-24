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

'''
name: dns-http,
S0: DNS_query,
S1: DNS_query_response,
S2: HTTP(GET).
associate可以理解为把其中的值提取出来，变成变量在自动机匹配中使用，其key必须唯一！
extract可以理解为拿出一些输出型数据，用于最后的语句输出
'''
test_dict = {
    'name': 'dns_http',
    'states_names': ['S0', 'S1', 'S2'],
    'head': 'S0',
    'states': [
        {
            'name': 'S0',
            'flag': 'DNS',
            'rule': [
                {'name': 'IP', 'match_dict': {'proto': 17}},
                {'name': 'UDP', 'match_dict': {'dport': 53}},
                {'name': 'DNS', 'match_dict': {'qr': 0}}
            ],

            'action': {
                'extract': [
                    {'layer': 'IP', 'extract_list': ['src', 'dst']},
                    {'layer': 'Time', 'extract_list': ['format_time']}
                    # {'layer': 'DNS', 'extract_list': ['qr']}
                ],
                'associate': [
                    'IP.src',
                    'IP.dst'
                ],
                'goto': 'S1'
            }
            
        },

        {
            'name': 'S1',
            'flag': 'DNS',
            'rule': [
                {'name': 'State', 'match_dict': {'IP.src': 'S0.dst', 'IP.dst': 'S0.src'}},
                {'name': 'UDP', 'match_dict': {'sport': 53}},
                {'name': 'DNS', 'match_dict': {'qr': 1}}
            ],

            'action': {
                'extract': [ 
                    # {'layer': 'DNS', 'extract_list': ['qr']}
                ],
                'associate': [
                    
                ],
                'goto': 'S2'
            }
        },

        {
            'name': 'S2',
            'flag': 'Raw',
            'rule': [
                {'name': 'State', 'match_dict': {'IP.src': 'S0.src'}},
                {'name': 'TCP', 'match_dict': {'dport': 80}},
                {'name': 'Raw', 'match_dict': { }}
            ],
            'action': {
                'extract': [
                    {'layer': 'IP', 'extract_list': ['dst']},
                    {'layer': 'Raw', 'extract_list': ['load']}
                ],
                'associate': [
                    
                ],
                'goto': ''
            }
        }
    ],
    
        # This format is experimental.
        # Use the extract keys above.
        # eg:
        # {}在{}时通过{}访问了目标主机{}，其payload为{}。
    
    'format': '%(S0.src)s在%(S0.format_time)s时通过%(S0.dst)s访问了目标主机%(S2.dst)s，其payload为%(S2.load)s。'
}

'''
name: S7_User_Data,
S0: S7COMM.
单包测试样例
'''
s7_test_dict = {
    'name': 'S7_User_Data',
    'states_names': ['S0'],
    'head': 'S0',
    'states': [
        {
            'name': 'S0',
            'rule': [
                {'name': 'S7COMM', 'match_dict': {'header_rosctr': '7'}}
            ],
            'action': {
                'extract': [
                    {'layer': 'S7COMM', 'extract_list': ['header_rosctr']}
                    ],
                'associate': [

                ],
                'goto': ''
            }
        }
    ],
    'format': '此次提取内容为%(S0.header_rosctr)s.'
}


# example
dict_switch_json(test_dict)
dict_switch_json(s7_test_dict)