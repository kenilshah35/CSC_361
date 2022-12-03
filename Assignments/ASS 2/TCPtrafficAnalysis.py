import sys
import struct

class IP_Header:
    src_ip = None #<type 'str'>
    dst_ip = None #<type 'str'>
    ip_header_len = None #<type 'int'>
    total_len = None    #<type 'int'>

    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0

    def ip_set(self,src_ip,dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip

    def header_len_set(self,length):
        self.ip_header_len = length

    def total_len_set(self, length):
        self.total_len = length

    def get_IP(self,buffer1,buffer2):
        src_addr = struct.unpack('BBBB',buffer1)
        dst_addr = struct.unpack('BBBB',buffer2)
        s_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
        d_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
        self.ip_set(s_ip, d_ip)

    def get_header_len(self,value):
        result = struct.unpack('B', value)[0]
        length = (result & 15)*4
        self.header_len_set(length)

    def get_total_len(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.total_len_set(length)

class TCP_Header:

    total_len = 0
    src_port = 0
    dst_port = 0
    seq_num = 0
    ack_num = 0
    data_offset = 0
    data_len = 0
    flags = {}
    window_size =0
    checksum = 0
    ugp = 0

    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.data_offset = 0
        self.flags = {}
        self.window_size =0
        self.checksum = 0
        self.ugp = 0

    def total_len_set(self, val):
        self.total_len = val

    def src_port_set(self, src):
        self.src_port = src

    def dst_port_set(self,dst):
        self.dst_port = dst

    def seq_num_set(self,seq):
        self.seq_num = seq

    def ack_num_set(self,ack):
        self.ack_num = ack

    def data_offset_set(self,data_offset):
        self.data_offset = data_offset

    def data_len_set(self, data_len):
        self.data_len = data_len

    def flags_set(self,ack, rst, syn, fin):
        self.flags["ACK"] = ack
        self.flags["RST"] = rst
        self.flags["SYN"] = syn
        self.flags["FIN"] = fin

    def win_size_set(self,size):
        self.window_size = size

    def get_src_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.src_port_set(port)
        #print(self.src_port)
        return None

    def get_dst_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.dst_port_set(port)
        #print(self.dst_port)
        return None

    def get_seq_num(self,buffer):
        seq = struct.unpack(">I",buffer)[0]
        self.seq_num_set(seq)
        #print(seq)
        return None

    def get_ack_num(self,buffer):
        ack = struct.unpack('>I',buffer)[0]
        self.ack_num_set(ack)
        return None

    def get_flags(self,buffer):
        value = struct.unpack("B",buffer)[0]
        fin = value & 1
        syn = (value & 2)>>1
        rst = (value & 4)>>2
        ack = (value & 16)>>4
        self.flags_set(ack, rst, syn, fin)
        return None
    def get_window_size(self,buffer1,buffer2):
        buffer = buffer2+buffer1
        size = struct.unpack('H',buffer)[0]
        self.win_size_set(size)
        return None

    def get_data_offset(self,buffer):
        value = struct.unpack("B",buffer)[0]
        length = ((value & 240)>>4)*4
        self.data_offset_set(length)
        #print(self.data_offset)
        return None

    def get_data_len(self):
        self.data_len_set(self.total_len - self.data_offset)

    def relative_seq_num(self,orig_num):
        if(self.seq_num>=orig_num):
            relative_seq = self.seq_num - orig_num
            self.seq_num_set(relative_seq)
        #print(self.seq_num)

    def relative_ack_num(self,orig_num):
        if(self.ack_num>=orig_num):
            relative_ack = self.ack_num-orig_num+1
            self.ack_num_set(relative_ack)

class packet():

    #pcap_hd_info = None
    IP_header = None
    TCP_header = None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    RTT_flag = False
    buffer = None
    connection_dir = None


    def __init__(self):
        self.IP_header = IP_Header()
        self.TCP_header = TCP_Header()
        #self.pcap_hd_info = pcap_ph_info()
        self.timestamp = 0
        self.packet_No =0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None

    def connection_dir_set(self, direction):
        self.connection_dir = direction

    def timestamp_set(self,buffer1,buffer2,orig_time):
        seconds = struct.unpack('I',buffer1)[0]
        microseconds = struct.unpack('<I',buffer2)[0]
        self.timestamp = round(seconds+microseconds*0.000001-orig_time,6)
        #print(self.timestamp,self.packet_No)
    def packet_No_set(self,number):
        self.packet_No = number
        #print(self.packet_No)

    def get_RTT_value(self,packet_timestamp):
        rtt = self.timestamp - packet_timestamp
        self.RTT_value = round(rtt,8)

class Connection():
    packet = None
    start_time = None
    end_time = None
    packet_list = None
    flags = {}
    orig_time = None
    RTT_list = None

    def __init__(self, orig_time, packet):
        self.packet = packet
        self.orig_time = orig_time
        self.start_time = None
        self.end_time = None
        self.packet_list = []
        self.RTT_list = []
        self.flags = {
            "SYN": 0,
            "FIN": 0,
            "RST": 0,
            "ACK": 0
        }
        self.get_packet_flags(packet)
        #self.get_packet_list(packet)

    def get_packet_flags(self, packet):

        if packet.TCP_header.flags["SYN"] == 1:
            self.flags["SYN"] = self.flags["SYN"] + 1
            self.start_time = packet.timestamp - self.orig_time
        if packet.TCP_header.flags["FIN"] == 1:
            self.flags["FIN"] = self.flags["FIN"] + 1
            self.end_time = packet.timestamp - self.orig_time
        if packet.TCP_header.flags["ACK"] == 1:
            self.flags["ACK"] = self.flags["ACK"] + 1
        if packet.TCP_header.flags["RST"] == 1:
            self.flags["RST"] = self.flags["RST"] + 1

        self.get_packet_list(packet)

    def get_packet_list(self, packet):

        self.packet_list.append(packet)

    def get_RTT_list(self, packet):
        self.RTT_list.append(packet.RTT_value)


def parse_packet(pd, time):

    IP_head = IP_Header()
    IP_head.get_IP(pd[26:30], pd[30:34])
    src_ip = IP_head.src_ip
    dst_ip = IP_head.dst_ip
    #print("Source IP:",IP_head.src_ip)
    #print("Dest IP:",IP_head.dst_ip)
    IP_head.get_header_len(pd[14:15])
    #print("IHL",IP_head.ip_header_len)
    IHL = IP_head.ip_header_len

    tcp_head = pd[14+IHL:]
    TCP_head = TCP_Header()

    TCP_head.total_len_set(len(tcp_head))
    total_len = TCP_head.total_len
    #print("Total length of TCP header:", total_len)

    TCP_head.get_src_port(tcp_head[:2])
    src_port = TCP_head.src_port
    #print("Source port", src_port)

    TCP_head.get_dst_port(tcp_head[2:4])
    dst_port = TCP_head.dst_port
    #print("Dest Port", dst_port)

    TCP_head.get_seq_num(tcp_head[4:8])
    seq_num = TCP_head.seq_num
    #print("Sequence number: ", seq_num)

    TCP_head.get_ack_num(tcp_head[8:12])
    ack_num = TCP_head.ack_num
    #print("Acknowledgement number:", ack_num)

    TCP_head.get_flags(tcp_head[13:14])
    flags = TCP_head.flags
    #print("Flags:", flags)

    TCP_head.get_window_size(tcp_head[14:15], tcp_head[15:16])
    window_size = TCP_head.window_size
    #print("Window Size:", window_size)

    TCP_head.get_data_offset(tcp_head[12:13])
    data_offset = TCP_head.data_offset
    #print("Data Offset:", data_offset)

    TCP_head.get_data_len()
    data_len = TCP_head.data_len
    #print("Data Length:", data_len)

    my_packet = packet()
    my_packet.IP_header = IP_head
    my_packet.TCP_header = TCP_head
    my_packet.timestamp = time
    #print(my_packet.TCP_header.seq_num)

    return my_packet

def analyse_packet(my_packet, orig_time, connection_dict, complete_connection_list, partial_connections):

    connection_direction = "{}:{} -> {}:{}".format(my_packet.IP_header.src_ip, my_packet.TCP_header.src_port, my_packet.IP_header.dst_ip, my_packet.TCP_header.dst_port)
    #print(connection_direction)
    #if src < dest:
        #connection_direction = "{}:{}->{}:{}".format(src, src_port, dest, dst_port)
        #print("1:", connection_direction)
    #elif src > dest:
        #connection_direction = "{}:{}->{}:{}".format(dest, dst_port, src, src_port)
        #print("2:", connection_direction)
    #elif port1 < port2:
        #connection_direction = "{}:{}->{}:{}".format(src, src_port, dest, dst_port)
        #print("3:", connection_direction)
    #else:
        #connection_direction = "{}:{}->{}:{}".format(dest, dst_port, src, src_port)
        #print("4:", connection_direction)

    if my_packet.connection_dir is None:
        my_packet.connection_dir_set(connection_direction)
    #print(connection_direction)
    #print(my_packet.TCP_header.seq_num + my_packet.TCP_header.data_offset)

    if my_packet.connection_dir in connection_dict:
        connection_dict[my_packet.connection_dir].get_packet_flags(my_packet)

        partial_connections.update({str(my_packet.TCP_header.seq_num + my_packet.TCP_header.data_len) : my_packet.timestamp})
        if my_packet.TCP_header.flags["ACK"] == 1:
            #print(my_packet.TCP_header.seq_num + my_packet.TCP_header.data_len)
            if str(my_packet.TCP_header.ack_num) in partial_connections:
                my_packet.get_RTT_value(partial_connections[str(my_packet.TCP_header.ack_num)])
                connection_dict[my_packet.connection_dir].get_RTT_list(my_packet)
                del partial_connections[str(my_packet.TCP_header.ack_num)]

    else:
        new_connection = Connection(orig_time, my_packet)
        connection_dict.update({connection_direction : new_connection})
        complete_connection_list.append(connection_direction)


def print_solution(connection_dict, complete_connection_list):

    # OUTPUT PART - A
    total_connections = len(complete_connection_list)
    print("\nA) Total number of connections: {}".format(total_connections))
    print("\n--------------------------------------------------------------------------------------------------------------------\n")

    # OUTPUT PART - B
    print("B) Connections'details\n")
    index = 0
    for dir in complete_connection_list:
        conn = connection_dict[dir]
        print("Connection {}:".format(index+1))
        print("Source Address: {}".format(conn.packet.IP_header.src_ip))
        print("Destination Address: {}".format(conn.packet.IP_header.dst_ip))
        print("Source Port: {}".format(conn.packet.TCP_header.src_port))
        print("Destination Port: {}".format(conn.packet.TCP_header.dst_port))

        if conn.flags["FIN"] > 0:
            print("Status:")

            print("Start time: {}".format(conn.start_time))
            print("End time: {}".format(conn.end_time))
            duration = conn.end_time - conn.start_time
            print("Duration: {}".format(duration))

            total_packets = len(conn.packet_list)
            print("Total number of packets: {}".format(total_packets))

            total_data = 0
            for packet in conn.packet_list:
                total_data = total_data + packet.TCP_header.data_len
            print("Total number of data bytes: {}".format(total_data))

        print("END")
        print("\n+++++++++++++++++++++++++++++++++\n")
        index = index + 1
    print("\n--------------------------------------------------------------------------------------------------------------------\n")

    # OUTPUT PART - C
    print("C) General")

    total_complete_connections = 0
    total_reset_connections = 0
    for dir in connection_dict:
        conn = connection_dict[dir]
        if conn.flags["FIN"] > 0:
            total_complete_connections = total_complete_connections + 1
        if conn.flags["RST"] > 0:
            total_reset_connections = total_reset_connections + 1
    print("Total number of complete TCP connections: {}".format(total_complete_connections))
    print("Number of reset TCP connections: {}".format(total_reset_connections))
    open_connections = total_connections - total_complete_connections
    print("Number of TCP connections that were still open when the trace capture ended: {}".format(open_connections))

    print("\n--------------------------------------------------------------------------------------------------------------------\n")

    # OUTPUT PART - D
    print("D) Complete TCP connections:")

    times_list = []
    combined_rtt_list = []
    packet_count_list = []
    window_list = []
    for dir in connection_dict:
        conn = connection_dict[dir]

        if conn.end_time is not None:
            times_list.append(conn.end_time - conn.start_time)

        for rtt in conn.RTT_list:
            combined_rtt_list.append(rtt)

        packet_count_list.append(len(conn.packet_list))

        for packet in conn.packet_list:
            window_list.append(packet.TCP_header.window_size)

    min_time = min(times_list)
    max_time = max(times_list)
    mean_time = sum(times_list)/len(times_list)
    print("Minimum time duration: {}".format(min_time))
    print("Mean time duration: {}".format(mean_time))
    print("Maximum time duration: {}".format(max_time))
    print()

    min_rtt = min(combined_rtt_list)
    max_rtt = max(combined_rtt_list)
    mean_rtt = sum(combined_rtt_list)/len(combined_rtt_list)
    print("Minimum RTT value: {}".format(min_rtt))
    print("Mean RTT value: {}".format(mean_rtt))
    print("Maximum RTT value:".format(max_rtt))
    print()

    min_pc = min(packet_count_list)
    max_pc = max(packet_count_list)
    mean_pc = sum(packet_count_list)/len(packet_count_list)
    print("Minimum number of packets including both send/received: {}".format(min_pc))
    print("Mean number of packets including both send/received: {}".format(mean_pc))
    print("Maximum number of packets including both send/received: {}".format(max_pc))
    print()

    min_ws = min(window_list)
    max_ws = max(window_list)
    mean_ws = sum(window_list)/len(window_list)
    print("Minimum receive window size including both send/received: {}".format(min_ws))
    print("Mean receive window size including both send/received: {}".format(mean_ws))
    print("Maximum receive window size including both send/received: {}".format(max_ws))

    print("\n--------------------------------------------------------------------------------------------------------------------\n")

def main():

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

    orig_time = None
    connection_dict = {}
    complete_connection_list = []
    partial_connections = {}
    while True:
        ph = f.read(16)
        if len(ph) == 0:
            break

        incl_len = struct.unpack('IIII', ph)[2]
        ts_sec = struct.unpack('IIII', ph)[0]
        ts_msec = struct.unpack('IIII', ph)[1]

        time = ts_sec + ts_msec*0.0000001

        if orig_time is None:
            orig_time = time

        pd = f.read(incl_len)
        protocol = struct.unpack('B',pd[23:24])
        if protocol != (6,):
            #print("not TCP")
            continue
        new_packet = parse_packet(pd, time)
        analyse_packet(new_packet, orig_time, connection_dict, complete_connection_list, partial_connections)

    print_solution(connection_dict, complete_connection_list)

if __name__ == "__main__":
    main()
