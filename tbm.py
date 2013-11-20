# remember: sudo python tbm.py

import argparse
import eventlet
import pcap
import umsgpack

eths = ["lo", "any", "eth0"]
devs = {}
clients = []


def print_packet(length, data, timestamp, fd):
    message = {"ln": length, "ts": timestamp, "if": devs[fd], "fd": fd, "dt": data}
    clients_copy = clients
    for client in clients_copy:
        try:
            client.write(umsgpack.packb(message))
            client.flush()
        except eventlet.green.socket.error:
            print "client {0} disconnected".format(client.fileno())
            clients.remove(client)
    #print "len: {0}, time: {1}, data:\n{2}\n".format(length, timestamp, data.encode("hex"))


def handle_eth(dev):
    while True:
        eventlet.hubs.trampoline(dev.fileno(), read=True)
        dev.dispatch(0, lambda l, d, t: print_packet(l, d, t, dev.fileno()))


def handle_client(fd):
    print "client {0} connected".format(fd.fileno())
    clients.append(fd)

parser = argparse.ArgumentParser(description='TODO describe program')
parser.add_argument('-c', '--client', action='store_true', help='run as client (default: server)', default=False)
args = parser.parse_args()

is_client = args.client

if is_client:
    print "TODO"
    pass
else:
    for eth in eths:
        dev = pcap.pcapObject()
        dev.open_live(eth, 1600, 1, 0)
        devs[dev.fileno()] = eth
        eventlet.spawn(handle_eth, dev)
    print "server socket listening on port 6000"
    server = eventlet.listen(('0.0.0.0', 6000))
    while True:
        eventlet.sleep(0)
        new_sock, address = server.accept()
        print "accepted", address
        eventlet.spawn(handle_client, new_sock.makefile('w'))
