'''
Protocol: The prototype of all protocol.
Contain normal_field and map(higher_word -> normal_field)
'''

from collections import Counter
from abc import ABCMeta, abstractmethod


class Protocol(metaclass=ABCMeta):
    name = "Protocol"
    normal_field = dict()
    map_table = dict()

    def map_find(self, map_table, pair: dict) -> int:
        for key in map_table.keys():
            if key in list(pair.keys()):
                return True
        return False

    @abstractmethod
    def make_map(self, map_table, pair):
        pass


    
class DNS(Protocol):
    name = "DNS"
    normal_field = {}
    map_table = {"域名": 'Domain', "网站": 'Domain', "无用": None}

    def make_map(self, map_table, pair):
        map_table.append(pair)
        return super().make_map(map_table)


if __name__ == '__main__':
    a = {"域名": 'Domain', "网站": 'Domain', "无用": None}
    c = Counter(a)
    print(c['域名'])
    test_dns = DNS()
    print(test_dns.name)
    print(test_dns.map_table)

    one = {"域名": 'Domain'}
    print(list(one.keys()))
    print(test_dns.map_find(test_dns.map_table, one))
