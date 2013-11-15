# remember: sudo python tbm.py

import pcap
import eventlet


eths = ["lo", "any", "eth0"]
devs = {}

def print_packet(length, data, timestamp):
    print "len: {0}, time: {1}, data:\n{2}\n".format(length, timestamp, data.encode("hex"))


def handle(dev):
    while True:
        print "? Waiting for {0} ({1})".format(devs[dev.fileno()], dev.fileno())
        eventlet.hubs.trampoline(dev.fileno(), read=True)
        print "... Reading from {0} ({1})".format(devs[dev.fileno()], dev.fileno())
        dev.dispatch(1, print_packet)
        print "! Read from {0} ({1})".format(devs[dev.fileno()], dev.fileno())

for eth in eths:
    dev = pcap.pcapObject()
    dev.open_live(eth, 1600, 1, 0)
    devs[dev.fileno()] = eth
    eventlet.spawn(handle, dev)

while True:
    eventlet.sleep(0)
