import sys
import struct
import statistics

class IPHeader:
    time = None
    eth = []
    ipv4 = []
    data = []
    len = None
    id = None
    flags = None
    offset = None
    ttl = None
    protocol = None
    src_ip = None
    dest_ip = None
    last_fragment = None

    def __init__(self, header, time):
        output = []
        for byte in header:
            output.append(byte)
        self.time = time
        self.eth = output[0x00:0x0e]
        self.ipv4 = output[0x0e:0x22]
        self.data = output[0x22:]

        self.len = self.ipv4[0x02] * 256 + self.ipv4[0x03]
        self.id = self.ipv4[0x04] * 256 + self.ipv4[0x05]
        self.flags = self.ipv4[0x06] & 0xe0
        self.offset = ((self.ipv4[0x06] & 0x1f) * 256 + self.ipv4[0x07]) * 8
        self.ttl = self.ipv4[0x08]
        self.protocol = self.ipv4[0x09]
        self.src_ip = self.ipv4[0x0c:0x10]
        self.dest_ip = self.ipv4[0x10:0x14]


        if self.flags == 0x20:
            self.last_fragment = True
        else:
            self.last_fragment = False

class Packet:

    def __init__(self, fragment):
        self.fragment_list = []
        self.time = fragment.time
        self.id = fragment.id
        self.src_ip = fragment.src_ip
        self.dest_ip = fragment.dest_ip
        self.total_len = None
        self.set_protocol(fragment.protocol)
        #self.fragment_list.append(fragment)
        self.append_fragment(fragment)

    def set_protocol(self, protocol):
        if protocol == 0x01:
            self.protocol = "ICMP"
        elif protocol == 0x11:
            self.protocol = "UDP"
        else:
            self.protocol = None

    def append_fragment(self,fragment):
        self.fragment_list.append(fragment)
        if fragment.flags == 0x00:
            self.total_len = fragment.offset + fragment.len - 20
            #print(self.total_len)
        if self.packet_complete():
            self.merge_fragment()


    def merge_fragment(self):

        output = []
        for fragment in self.fragment_list:
            output.extend(fragment.data)

        if self.protocol == "UDP":
            header = output
            self.src_port = header[0x00]*256 + header[0x01]
            self.dest_port = header[0x02]*256 + header[0x03]

        elif self.protocol == "ICMP":
            header = output
            #print(header[0x00])
            if header[0x00] == 0:
                self.type = "INVALID"
            elif header[0x00] == 3:
                self.type = "DESTINATION_UNREACHABLE"
            elif header[0x00] == 5:
                self.type = "REDIRECT"
            elif header[0x00] == 8:
                self.type = "ECHO"
            elif header[0x00] == 11:
                self.type = "TIME_EXCEEDED"
            elif header[0x00] == 12:
                self.type = "PARAMETER_PROBLEM"
            else:
                print("Invalid icmp parameter")
                sys.exit(1)

            if self.type == "ECHO":
                #print("hi echo")
                self.seq = header[0x06]*256 + header[0x07]
            elif self.type == "TIME_EXCEEDED":
                #print("hi time")
                ip_req_header = header[0x08:0x1c]
                icmp_req_header = header[0x1c:]
                self.req_id = ip_req_header[0x04]*256 + ip_req_header[0x05]
                self.req_src_ip = ip_req_header[0x0c:0x10]
                self.req_dest_ip = ip_req_header[0x10:0x14]
                if icmp_req_header[0x00] == 8:
                    self.req_seq = icmp_req_header[0x06]*256 + icmp_req_header[0x07]
                else:
                    udp_req_header = header[0x1c:0x25]
                    self.req_src_port = udp_req_header[0x00]*256 + udp_req_header[0x01]
                    self.req_dest_port = udp_req_header[0x02]*256 + udp_req_header[0x03]

    def packet_complete(self):
        frags_data_len = sum([len(frag.data)
                              for frag in self.fragment_list])
        if self.total_len is not None:
            if frags_data_len == self.total_len:
                #print("anyone")
                return True
        return False


    def connection_direction(self):
        ip = '.'.join(str(seg) for seg in self.src_ip)

        if self.protocol == "UDP":
            return "src-{}:{}".format(ip, self.src_port)
        elif self.protocol == "ICMP":
            if self.type == "ECHO":
                return "src-{}--{}".format(ip, self.seq)
            elif self.type == "TIME_EXCEEDED":
                req_ip = '.'.join(str(seg) for seg in self.req_src_ip)
                if self.req_seq is not None:
                    return "src-{}--{}".format(req_ip, self.req_seq)
                else:
                    return "src-{}:{}".format(req_ip, self.req_src_port)

class Trace:

    def __init__(self, packet, orig_time):
        self.orig_time = orig_time
        self.direction = None
        self.platform = None
        self.start_time = None
        self.probe_packet = None
        self.resp_packet = None
        self.end_time = None
        self.add_probe(packet)

    def get_direction(self):
        return self.direction

    def get_src_ips(self):
        if self.probe_packet is not None and self.resp_packet is not None:
            #print("me")
            return (self.probe_packet.src_ip, self.resp_packet.src_ip)
        elif self.probe_packet is not None:
            #print("nijirke")
            return (self.probe_packet.src_ip, None)
        #print("fjd")
        return (None,None)

    #def get_src_ports(self):
        #if self.probe_packet is not None and self.resp_packet is not None:
                #return (self.probe_packet.src_port, self.resp_packet.src_port)
            #elif self.probe_packet is not None:
                #return (self.probe_packet.src_port, None)
            #return (None, None)

    def get_ips_direction(self):
        ips = self.get_src_ips()
        ip1 = '.'.join(str(i) for i in ips[0])
        ip2 = '.'.join(str(i) for i in ips[1])

        if ip1 < ip2:
            return "{}->{}".format(ip1, ip2)
        elif ip1 > ip2:
            return "{}->{}".format(ip2, ip1)
        return "{}->{}".format(ip1, ip2)

    def get_trace_duration(self):
        if self.end_time is None:
            return [None]
        #print("hi")
        return [self.end_time - fragment.time for fragment in self.probe_packet.fragment_list]

    def get_probe_fragments(self):
        return self.probe_packet.fragment_list

    def add_probe(self, packet):
        if self.probe_packet is None:
            self.start_time = packet.time
            self.probe_packet = packet
            ip = '.'.join(str(seg) for seg in packet.src_ip)
            if packet.protocol == "UDP":
                self.direction = "src-{}:{}".format(ip, packet.src_port)
            elif packet.protocol == "ICMP":
                if packet.type == "ECHO":
                    self.direction = "src-{}--{}".format(ip, packet.seq)
                else:
                    self.direction = "src-{}--{}".format(ip, packet.req_seq)
        else:
            self.probe_packet.append_fragment(packet)

    def add_response(self, packet):
        self.ip_tuple = (packet.req_src_ip, packet.src_ip)
        self.end_time = packet.time
        self.resp_packet = packet

class IPTraceSession:

    def __init__(self):
        self.trace_dict = {}
        self.trace_list = []
        self.orig_time = None
        self.partial_packets = {}

    def analyse_packet(self, header, time):
        fragment = IPHeader(header, time)
        if fragment.id in self.partial_packets:
            packet = self.partial_packets[fragment.id]
            packet.append_fragment(fragment)
        else:
            packet = Packet(fragment)
            self.partial_packets[packet.id] = packet

        if self.orig_time is None:
            self.orig_time = packet.time

        if packet.packet_complete():
            del self.partial_packets[packet.id]

            if ((packet.protocol == "ICMP" and packet.type == "ECHO") or (packet.protocol == "UDP")):
                self.trace_dict[packet.connection_direction()] = Trace(packet, self.orig_time)
                self.trace_list.append(packet.connection_direction())

            elif packet.protocol == "ICMP" and packet.type == "TIME_EXCEEDED":
                if packet.connection_direction() in [trace.get_direction() for trace in self.trace_dict.values()]:
                    self.trace_dict[packet.connection_direction()].add_response(packet)

def get_ips_direction(ips):
    ip1 = '.'.join(str(i) for i in ips[0])
    ip2 = '.'.join(str(i) for i in ips[1])

    if ip1 < ip2:
        return "{}->{}".format(ip1, ip2)
    elif ip1 > ip2:
        return "{}->{}".format(ip2, ip1)
    return "{}->{}".format(ip1, ip2)

def print_solution(trace_sesh):

    finished_traces = []
    #print(trace_sesh.trace_list)
    #print(trace_sesh.trace_dict)
    for id in trace_sesh.trace_list:
        #print(trace_sesh.trace_dict[id])
        #print(trace_sesh.trace_dict[id].resp_packet.type)
        if (trace_sesh.trace_dict[id].resp_packet and trace_sesh.trace_dict[id].resp_packet.type == "TIME_EXCEEDED"):
            finished_traces.append(trace_sesh.trace_dict[id])

    trace_ip_list = []
    trace_rtts_dict = {}
    #print(finished_traces)
    for trace in finished_traces:
        #print("probs")
        #print(trace.get_src_ips())
        if trace.get_src_ips() not in trace_ip_list:
            #print("hi")
            trace_ip_list.append(trace.get_src_ips())
            trace_rtts_dict[trace.get_ips_direction()] = trace.get_trace_duration()
        else:
            trace_rtts_dict[trace.get_ips_direction()].extend(trace.get_trace_duration())
            #print("hi")

    print("The IP address of the source node: {}\n".format(".".join(map(str, trace_ip_list[0][0]))))
    print("The IP address of the ultimate destination: {}\n".format(".".join(map(str, finished_traces[0].probe_packet.dest_ip))))

    print("The IP addresses of the intermediate destination nodes:")

    for i,j in enumerate(trace_ip_list):
        print("\trouter {} : {},".format(i+1, ".".join(map(str,j[1]))))
    print("\n")

    protocols = []
    for trace in trace_sesh.trace_dict.values():
        if trace.probe_packet.protocol not in protocols:
            protocols.append(trace.probe_packet.protocol)

        if trace.resp_packet is not None:
            if trace.resp_packet.protocol not in protocols:
                protocols.append(trace.resp_packet.protocol)
    print("The values in the protocol field of IP headers:")
    for i in protocols:
        if i == "ICMP":
            print("\t {}: {}\n".format("1", i))
        elif i == "UDP":
            print("\t {}: {}\n".format("17", i))
        else:
            print("\t {}: {}".format("number", i))

    

    #print(trace_rtts_dict)
    for i in trace_ip_list:

        rtts = trace_rtts_dict[get_ips_direction(i)]

        print("The avg RTT between {} and {} is: ".format(".".join(map(str,i[0])), ".".join(map(str,i[1]))))
        print("{0:.3f}ms, ".format(statistics.mean(rtts)))
        print("the s.d is: {0:.1f}ms".format(0 if len(rtts) < 2 else statistics.stdev(rtts)))


def main():

    #Checking if filename entered during execution
    try:
        if sys.argv[1] is None:
            print("Enter valid pcap filename")
        else:
            fileName = sys.argv[1]
    except:
        print("error exiting")
        sys.exit(1)

    try:
        f = open(fileName, "rb")
    except:
        print("Error while opening pcap file")
        sys.exit(1)

    globalHeader = f.read(24)
    trace_sesh = IPTraceSession()

    while True:
        ph = f.read(16)
        if len(ph) == 0:
            break

        incl_len = struct.unpack('IIII', ph)[2]
        ts_sec = struct.unpack('IIII', ph)[0]
        ts_msec = struct.unpack('IIII', ph)[1]

        time = ts_sec + ts_msec*0.0000001

        #if orig_time is None:
            #orig_time = time

        pd = f.read(incl_len)
        trace_sesh.analyse_packet(pd, time)

    print_solution(trace_sesh)

if __name__ == "__main__":
    main()
