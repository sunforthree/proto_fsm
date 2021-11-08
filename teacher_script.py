

class State(object):
    name = ''
    transtions = []

class Rule():
    match_objs = []

class Trans(object):
    rule = Rule()
    target = ''
    actions = ''

class MatchObj:
    parser = ''
    dicts = {}

input_dict = {}
s = State()

for t in s.transtions:
    if input_dict.match(t.rule):
        s = t.target