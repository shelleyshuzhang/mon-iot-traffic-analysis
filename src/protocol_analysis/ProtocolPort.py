class ProtocolPort(object):

    def __init__(self, protocol_port, encrypted, expected, readable, importance):
        self.protocol_port = protocol_port
        self.encrypted = encrypted
        self.well_known = expected
        self.readable = readable
        self.imp = importance

    def __eq__(self, other):
        return isinstance(other, ProtocolPort) \
               and self.protocol_port == other.protocol_port \
               and self.encrypted == other.encrypted \
               and self.well_known == other.well_known \
               and self.readable == other.readable \
               and self.imp == other.imp

    def __hash__(self):
        hash((self.protocol_port,
              self.encrypted,
              self.well_known,
              self.readable,
              self.imp))

