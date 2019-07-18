import socket, sys
from struct import *


# uzkuriam socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error, msg:
    #apsauga nuo admin teisiu neturejimo
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

#gaunam
while True:
    packet = s.recvfrom(65565)

    # parodom kad cia tuplas
    packet = packet[0]

    # paimam pirmus 20 simboliu is IP headerio
    ip_header = packet[0:20]

    # ispakuojam
    iph = unpack('!BBHHHBBH4s4s', ip_header)

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF

    iph_length = ihl * 4
    #load_layer("tls")
    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8]);
    d_addr = socket.inet_ntoa(iph[9]);
    try:
        print 'ipv' + str(version) +' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)+' tls '+str(ttl)
    except socket.error:
        pass
    tcp_header = packet[iph_length:iph_length + 20]

    # sustatom kur mus dominantys paketo duomenys
    tcph = unpack('!HHLLBBHHH', tcp_header)

    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4

    print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port)

    h_size = iph_length + tcph_length * 4
    data_size = len(packet) - h_size

    # imam data
    data = packet[h_size:]

    #gaudom slacka jei yra stringe toks irasas tai printima yes jei ne tai no
    if s_addr.find("143.204.93.160") != -1:#amazon
        print("yes")
    if s_addr.find("54.192.200.27") != -1:#cujo.slack.com
        print("yes")
    else:
        print("no")
    #paylaudo spausdinimas
    #print 'Data : ' + data
    #print
