# remember: sudo python tbm.py

import argparse
import eventlet
import os
import pcap
import socket
import msgpack

#TODO: requirements.txt
#TODO: logging


def send_packet(packet, dev_id):
    (length, data, timestamp) = packet
    if length > 20000:
        print "WARNING: Large packet: {0} (sniffing loop?)".format(length)
    message = {"ln": length, "ts": timestamp, "if": devs[dev_id]["eth"], "id": dev_id, "dt": data}
    clients_copy = clients
    for client in clients_copy:
        try:
            msgpack.pack(message, client)
            client.flush()
        except eventlet.green.socket.error:
            print "client disconnected (fd: {0})".format(client.fileno())
            clients.remove(client)


def receive_packet(message):
    if len(devs) <= message["id"]:
        print "Nowhere to forward packet, dropping it."
    else:
        dev = devs[message["id"]]
        print "time: {0}, src_interface: {1}, dst_interface: {2}, len: {3}".format(message["ts"], message["if"],
                                                                                   dev["eth"], message["ln"])
        os.write(dev["dev"].fileno(), message["dt"])


def handle_eth(dev_id):
    while True:
        dev = devs[dev_id]["dev"]
        eventlet.hubs.trampoline(dev.fileno(), read=True)
        send_packet(dev.next(), dev_id)


def handle_client_connected(fd):
    print "client connected (fd: {0})".format(fd.fileno())
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
                receive_packet(message)
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
    devs = []
    for (id, eth) in enumerate(eths):
        dev = pcap.pcapObject()
        dev.open_live(eth, 1500, 1, 0)
        devs.append({"dev": dev, "eth": eth})
        eventlet.spawn(handle_eth, id)
    return devs


parser = argparse.ArgumentParser(description="TODO describe program")
parser.add_argument("-c", "--client", metavar="HOST", help="run as client, connect to HOST", default=None, dest="host")
parser.add_argument("-p", "--port", type=int, help="port of communication", default=6000)
parser.add_argument("interfaces", metavar="IF", nargs="+", help="interfaces to tunnel")
#TODO: debug / minimal mode?
args = parser.parse_args()

clients = []
devs = open_eths(args.interfaces)

if args.host is None:
    start_server(args.port)
else:
    start_client(args.host, args.port)
