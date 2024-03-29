'''
    This project is from littlezz in Github, the url is https://github.com/littlezz/scapy2dict/blob/master/scapy2dict.py
    Why I rewrite is the old scapy2dict can't run in python3 and the latest scapy.
    ChainMap is a bigger dict and it can put multi-dicts to a list.

    Date: 2022-02-24
    Q: Don't have time.
    TODO: Insert time to the dict.
'''

from collections import ChainMap
import time

__all__ = ['to_dict', 'Packet2Dict']

_native_value = (int, float, str, bytes, bool, list, tuple, set, dict, type(None))

def to_dict(pkt, strict=False):
    """
    return ChainMap dict. if strict set to True, return dict.
    """
    d = Packet2Dict(pkt).to_dict()
    return d if not strict else dict(**d)


def _layer2dict(obj):
    d = {}

    if not getattr(obj, 'fields_desc', None):
        return
    for f in obj.fields_desc:
        value = getattr(obj, f.name)
        if value is type(None):
            value = None

        if not isinstance(value, _native_value):
            value = _layer2dict(value)
        d[f.name] = value
    return {obj.name: d}


class Packet2Dict:
    def __init__(self, pkt):
        self.pkt = pkt


    def to_dict(self):
        """
        Turn every layer to dict, store in ChainMap type.
        :return: ChainMaq
        """
        d = list()
        count = 0

        while True:
            layer = self.pkt.getlayer(count)
            if not layer:
                break
            d.append(_layer2dict(layer))

            count += 1

        '''
        Add time.
        format: %Y-%m-%d %H:%M:%S.
        '''
        time_local = time.localtime(self.pkt.time)
        dt = time.strftime("%Y-%m-%d %H:%M:%S", time_local)
        time_dict = dict(Time= {'format_time': dt})
        d.append(time_dict)
        
        return ChainMap(*d)