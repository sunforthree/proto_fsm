'''
proto_fsm's state.
Class:
    State
    Rule(has Parser)
    Parser
    Action
该文件改写于./old_version/Machine.py
'''
class State:
    def __init__(self, name, Rule, Action):
        print('A new state named %s has been created.' % name)
        self.name = name
        self.Rule = Rule
        self.Action = Action

    def get_name(self):
        return self.name
    
    def get_Rule(self):
        return self.Rule

    def get_Action(self):
        return self.Action

# find a dict of rules.
# rule_list: a list of Parsers.
class Rule:
    def __init__(self, rule_list):
        self.rule_list = rule_list
    def get_rule_list(self):
        return self.rule_list

# Parser
class Parser:
    def __init__(self, layer, match_dict):
        self.layer = layer
        self.match_dict = match_dict

    def get_layer(self):
        return self.layer

    def get_match_dict(self):
        return self.match_dict

# After matching. what to do
class Action:
    def __init__(self, extract_dict, associate_list):
        self.extract_dict = extract_dict
        self.associate_list = associate_list
        self.goto = ''

    def get_extract_list(self):
        return self.extract_dict

    def get_associate_list(self):
        return self.associate_list

    def set_goto(self, goto):
        self.goto = goto

    def get_goto(self):
        return self.goto

    def ok(self):
        print('This is the last state, parsering is OK!')