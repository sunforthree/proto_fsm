from os.path import abspath, dirname
import json
from scapy.all import rdpcap, ls
from scapy2dict import to_dict

# switch the dict to the json file.
# write it in ./fsm_model
def dict_switch_json(fsm_dict={}):
    # file_name = '{name}.{type}'
    # file_name = abspath(dirname(__file__)) + "\\fsm_model\\" + file_name.format(name=fsm_dict['name'], type='json')

    jsObj = json.dumps(fsm_dict)
    print(type(jsObj))
    print(jsObj)
    # fileObject = open(file_name, mode='w')
    # fileObject.write(jsObj)
    # fileObject.close()


if __name__ == '__main__':
    # test_dict = {'frame': {'frame.timestamp': '1637067007719221', 'frame.number': '1', 'frame.len': '153', 'frame.protocols': 'ether:IP:TCP:HTTP'}, 'ether': {'ether.dst': '20:76:93:00:97:70', 'ether.src': 'a0:8c:fd:c1:0b:2d', 'ether.type': '2048'}, 'IP': {'IP.src': '192.168.123.233', 'IP.dst': '35.232.111.17'}, 'TCP': {'TCP.sport': '49790', 'TCP.dport': '80', 'TCP.seq': '3415042011', 'TCP.ack': '2648804415', 'TCP.flags': "['P', 'A']"}, 'HTTP': {'HTTP.Method': "b'GET'", 'HTTP.Path': "b'/'", 'HTTP.Http_Version': "b'HTTP/1.1'"}}
    # print(test_dict)
    # dict_switch_json(test_dict)
    packet_list = rdpcap('dns_http_3packages.pcapng')
    ls(packet_list[2])
    print(to_dict(packet_list[2]))
    print(to_dict(packet_list[0]).get('Raw'))