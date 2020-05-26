class DestinationPro(object):

    def __init__(self, dst, pro_port):
        self.host = dst
        self.protocol_port = pro_port
        self.snd = 0
        self.rcv = 0
        self.p_snd = 0
        self.p_rcv = 0

    def __eq__(self, other):
        #print("ODFIOSINDIIOOSFOOSIFN")
        #print(isinstance(other, DestinationPro), self.host == other.host, self.protocol_port == other.protocol_port)
        return isinstance(other, DestinationPro) \
               and self.host == other.host \
               and self.protocol_port == other.protocol_port

    def __hash__(self):
        hash((self.host, self.protocol_port))

    def add_snd(self, traffic):
        self.snd += int(traffic)

    def add_rcv(self, traffic):
        self.rcv += int(traffic)

    def add_ps(self, pak_num):
        self.p_snd += int(pak_num)

    def add_pr(self, pak_num):
        self.p_rcv += int(pak_num)

    def add_all(self, snd_traf, rcv_traf, pak_num_snd, pak_num_rcv):
        self.snd += snd_traf
        self.rcv += rcv_traf
        self.p_snd += pak_num_snd
        self.p_rcv += pak_num_rcv

    def print_all(self):
        print(self.snd, self.rcv, self.p_snd, self.p_rcv)
