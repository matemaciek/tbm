# remember: sudo python tbm.py

import argparse
import eventlet
import pcap
import socket
import msgpack # msgpack-python

#TODO: requirements.txt

devs = {}
clients = []


def print_packet(length, data, timestamp, fd):
    if length > 20000:
        print "WARNING: Large packet: {0} (sniffing loop?)".format(length)
    message = {"ln": length, "ts": timestamp, "if": devs[fd], "fd": fd, "dt": data}
    clients_copy = clients
    for client in clients_copy:
        try:
            msgpack.pack(message, client)
            client.flush()
        except eventlet.green.socket.error:
            print "client {0} disconnected".format(client.fileno())
            clients.remove(client)


def handle_eth(dev):
    while True:
        eventlet.hubs.trampoline(dev.fileno(), read=True)
        dev.dispatch(0, lambda l, d, t: print_packet(l, d, t, dev.fileno()))


def handle_client(fd):
    print "client {0} connected".format(fd.fileno())
    clients.append(fd)

parser = argparse.ArgumentParser(description="TODO describe program")
parser.add_argument("-c", "--client", action="store_true", help="run as client (default: server)", default=False)
parser.add_argument("-p", "--port", type=int, help="port of communication", default=6000)
parser.add_argument("interfaces", metavar="N", nargs="+", help="interfaces to tunnel")
args = parser.parse_args()

port = args.port
is_client = args.client
eths = enumerate(args.interfaces)  # "eth0", "any", "lo"

if is_client:
    s = socket.socket()
    host = socket.gethostname()  # TODO: host as argument
    s.connect((host, port))
    try:
        unpacker = msgpack.Unpacker()
        while True:
            buf = s.recv(2048)
            if not buf:
                break
            unpacker.feed(buf)
            for message in unpacker:
                print "time: {1}, interface: {2}, len: {0}\n".format(message["ln"], message["ts"], message["if"])
                assert message["ln"] == len(message["dt"]), "difference: {0}".format(message["ln"] - len(message["dt"]))
    except KeyboardInterrupt:
        s.close()
else:
    for (id, eth) in eths:
        dev = pcap.pcapObject()
        dev.open_live(eth, 65536, 1, 0)
        devs[dev.fileno()] = (id, eth)
        eventlet.spawn(handle_eth, dev)
    print "server socket listening on port {0}".format(port)
    server = eventlet.listen(('0.0.0.0', port))
    while True:
        new_sock, address = server.accept()
        print "accepted", address
        eventlet.spawn(handle_client, new_sock.makefile('w'))
