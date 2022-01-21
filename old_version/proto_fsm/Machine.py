# This file use to define the fsm.
from Event import Event
from scapy.all import *

# Parser
class Parser:
    def __init__(self, layer, match_dict):
        self.layer = layer
        self.match_dict = match_dict

    def get_layer(self):
        return self.layer

    def get_match_dict(self):
        return self.match_dict

# MatchObj
class MatchObj:
    def __init__(self, layer, match_dict):
        self.layer = layer
        self.match_dict = match_dict

    def get_layer(self):
        return self.layer

    def get_match_dict(self):
        return self.match_dict


# find a dict of rules.
# rule_list: a list of MatchObjs.
class Rule:
    def __init__(self, rule_list):
        self.rule_list = rule_list

    def get_rule_list(self):
        return self.rule_list

# After matching. what to do
class Action:
    goto = ''
    def __init__(self, extract_list):
        self.extract_list = extract_list

    def get_extract_list(self):
        return self.extract_list

    def ok(self):
        print('前方探索区域还未解锁，去下一个transition看看吧！')

"""
target_state: the destination.
              self_state
              another
              '' means end.
"""
class Transition:
    def __init__(self, Rule, Action):
        self.Rule = Rule
        self.Action = Action
        self.source_state = ''
        self.target_state = ''

    def get_Rule(self):
        return self.Rule
    
    def get_Action(self):
        return self.Action

    def set_source_state(self, source_state):
        self.source_state = source_state

    def get_source_state(self):
        return self.source_state

    def set_target_state(self, target_state):
        self.target_state = target_state

    def get_target_state(self):
        return self.target_state

    # action = ['goto', 'stay']

class State:
    def __init__(self, name, states = None):
        print("A new state named %s has been created" % (name))
        self.name = name
        self.states = states

    def get_name(self):
        return self.name

    def get_states(self):
        return self.normal['states']

"""
More information about Machine.
"""

class Machine:
    def __init__(self, data_set, state_set, trans_set, feature):
        print("A new machine has been defined.")
        self.data_set = data_set
        self.state_set = state_set
        self.trans_set = trans_set
        self.feature = feature

    # return the machine's feature.
    def get_feature(self, feature):
        return feature 