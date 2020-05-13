class Destination(object):

    def __init__(self, ip, host, party):
        self.ip = ip
        self.host = host
        self.party = party

    def __eq__(self, other):
        return isinstance(other, Destination) \
               and self.host == other.host \
               and self.party == other.party \
               and self.ip == other.ip

    def __hash__(self):
        hash((self.host, self.party, self.ip))
