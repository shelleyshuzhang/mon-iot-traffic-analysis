class Destination(object):
    def __init__(self, ip, host, party, host_full, country, org):
        self.ip = ip
        self.host = host
        self.party = party
        self.host_full = host_full
        self.country = country
        self.organization = org

    def __eq__(self, other):
        return isinstance(other, Destination) \
               and self.host == other.host \
               and self.party == other.party \
               and self.ip == other.ip

    def __hash__(self):
        hash((self.host, self.party, self.ip))
