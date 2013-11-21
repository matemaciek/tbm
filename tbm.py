# remember: sudo python tbm.py

import argparse
import eventlet
import pcap
import socket
import msgpack # msgpack-python

#TODO: requirements.txt


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


def handle_client_connected(fd):
    print "client {0} connected".format(fd.fileno())
    clients.append(fd)


def start_client(host, port):
    s = socket.socket()
    host = socket.gethostbyname(host)
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


def start_server(port):
    print "server socket listening on port {0}".format(port)
    server = eventlet.listen(('0.0.0.0', port))
    while True:
        new_sock, address = server.accept()
        print "accepted", address
        eventlet.spawn(handle_client_connected, new_sock.makefile('w'))


def open_eths(eths):
    for (id, eth) in eths:
        dev = pcap.pcapObject()
        dev.open_live(eth, 65536, 1, 0)
        devs[dev.fileno()] = (id, eth)
        eventlet.spawn(handle_eth, dev)

parser = argparse.ArgumentParser(description="TODO describe program")
parser.add_argument("-c", "--client", metavar="HOST", help="run as client, connect to HOST", default=None)
parser.add_argument("-p", "--port", type=int, help="port of communication", default=6000)
parser.add_argument("interfaces", metavar="IF", nargs="+", help="interfaces to tunnel")
#TODO: debug / minimal mode?
args = parser.parse_args()

devs = {}
clients = []

open_eths(enumerate(args.interfaces))
if args.client is None:
    start_server(args.port)
else:
    start_client(args.client, args.port)
