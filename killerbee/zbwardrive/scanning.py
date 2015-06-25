#!/usr/bin/env python

import datetime
import multiprocessing
import Queue
import signal
import time
import traceback

#import RPIO
#import RPi.GPIO as GPIO
from mapjson import MapJson

import sys
import string
import socket
import struct

from killerbee import *
from db import toHex
from capture import startCapture
try:
    from scapy.all import Dot15d4, Dot15d4Beacon
except ImportError:
    print 'This Requires Scapy To Be Installed.'
    from sys import exit
    exit(-1)

#TODO set iteration min to a sensical parameter
MIN_ITERATIONS_AGRESSIVE = 0

# doScan_processResponse
def doScan_processResponse(packet, channel, zbdb, kbscan, verbose=False, dblog=False):
    scapyd = Dot15d4(packet['bytes'])
    # Check if this is a beacon frame
    if isinstance(scapyd.payload, Dot15d4Beacon):
        if verbose: print "Received frame is a beacon."
        try:
            spanid = scapyd.src_panid
            source = scapyd.src_addr
        except Exception as e:
            print "DEBUG: Issue fetching src panid/addr from scapy packet ({0}).".format(e)
            print "\t{0}".format(scapyd.summary())
            print scapyd.show2()
            print "-"*25
            return None #ignore this received frame for now
        key = '%x%x' % (spanid, source)
        #TODO if channel already being logged, ignore it as something new to capture
        if zbdb.channel_status_logging(channel) == False:
            if verbose:
                print "A network on a channel that is not currently being logged replied to our beacon request."
            # Store the network in local database so we treat it as already discovered by this program:
            zbdb.store_networks(key, spanid, source, channel, packet['bytes'])
            # Log to the mysql db or to the appropriate pcap file
            if dblog == True:
                kbscan.dblog.add_packet(full=packet, scapy=scapyd)
            else:
                #TODO log this to a PPI pcap file maybe, so the packet is not lost? or print to screen?
                pass
            return channel
        else: #network designated by key is already being logged
            if verbose:
                print 'Received frame is a beacon for a network we already found and are logging.'
                return None
    else: #frame doesn't look like a beacon according to scapy
        return None
# --- end of doScan_processResponse ---

# doScan
def doScan_old(zbdb, currentGPS, verbose=False, dblog=False, agressive=False, staytime=2):
    # Choose a device for injection scanning:
    scannerDevId = zbdb.get_devices_nextFree()
    # log to online mysql db or to some local pcap files?
    kbscan = KillerBee(device=scannerDevId, datasource=("Wardrive Live" if dblog else None))
    #  we want one that can do injection
    inspectedDevs = []
    while (kbscan.check_capability(KBCapabilities.INJECT) == False):
        zbdb.update_devices_status(scannerDevId, 'Ignore')
        inspectedDevs.append(scannerDevId)
        kbscan.close()
        scannerDevId = zbdb.get_devices_nextFree()
        if scannerDevId == None:
            raise Exception("Error: No free devices capable of injection were found.")
        kbscan = KillerBee(device=scannerDevId, datasource=("Wardrive Live" if dblog else None))
    #  return devices that we didn't choose to the free state
    for inspectedDevId in inspectedDevs:
        zbdb.update_devices_status(inspectedDevId, 'Free')
    print 'Network discovery device is %s' % (scannerDevId)
    zbdb.update_devices_status(scannerDevId, 'Discovery')

    # Much of this code adapted from killerbee/tools/zbstumbler:main
    # Could build this with Scapy but keeping manual construction for performance
    beacon = "\x03\x08\x00\xff\xff\xff\xff\x07" #beacon frame
    beaconp1 = beacon[0:2]  #beacon part before seqnum field
    beaconp2 = beacon[3:]   #beacon part after seqnum field
    seqnum = 0              #seqnum to use (will cycle)
    channel = 11            #starting channel (will cycle)
    iteration = 0           #how many loops have we done through the channels?
    # Loop injecting and receiving packets
    while 1:
        if channel > 26:
            channel = 11
            iteration += 1
        if seqnum > 255: seqnum = 0
        try:
            #if verbose: print 'Setting channel to %d' % channel
            kbscan.set_channel(channel)
        except Exception as e:
            raise Exception('Failed to set channel to %d (%s).' % (channel,e))
        if verbose:
            print 'Injecting a beacon request on channel %d.' % channel
        try:
            beaconinj = beaconp1 + "%c" % seqnum + beaconp2
            kbscan.inject(beaconinj)
        except Exception, e:
            raise Exception('Unable to inject packet (%s).' % e)

        # Process packets for staytime (default 2 seconds) looking for the beacon response frame
        endtime = time.time() + staytime
        nonbeacons = 0
        while (endtime > time.time()):
            recvpkt = kbscan.pnext() #get a packet (is non-blocking)
            # Check for empty packet (timeout) and valid FCS
            if recvpkt != None and recvpkt['validcrc']:
                #if verbose: print "Received frame."
                newNetworkChannel = doScan_processResponse(recvpkt, channel, zbdb, kbscan, verbose=verbose, dblog=dblog)
                if newNetworkChannel != None:
                    startCapture(zbdb, newNetworkChannel, gps=currentGPS, dblog=dblog)
                    nonbeacons = 0 # forget about any non-beacons, as we don't care, we saw a beacon!
                    break          # made up our mind, stop wasting time
                elif agressive:    # we may care even though it wasn't a beacon
                    nonbeacons += 1
                    if verbose:
                        print 'Received frame (# %d) is not a beacon.' % nonbeacons, toHex(recvpkt['bytes'])

        # If we're in agressive mode and didn't see a beacon, we have nonbeacons > 0.
        # If we aren't logging the channel currently, and
        # If we have already tried a loop through without being agressive
        if nonbeacons > 0 and iteration > MIN_ITERATIONS_AGRESSIVE and zbdb.channel_status_logging(channel) == False:
            if verbose:
                print "Start capture on %d as a channel without beacon." % channel
            #TODO
            # Maybe just increase a count and increase stay time on this channel to see if we get a few packets, thus making us care?
            # Maybe also do at least a full loop first every so often before going after these random packets...
            startCapture(zbdb, channel, gps=currentGPS, dblog=dblog)
        #elif verbose:
        #    print "Had {0} nonbeacon packets on loop iteration {1} and found that channel {2} being already logged was {3}.".format(
        #        nonbeacons, iteration, channel, zbdb.channel_status_logging(channel))

        kbscan.sniffer_off()
        seqnum += 1
        channel += 1

    #TODO currently unreachable code, but maybe add a condition to break the infinite while loop in some circumstance to free that device for capture?
    kbscan.close()
    zbdb.update_devices_status(scannerDevId, 'Free')
# --- end of doScan ---


# TODO: we're currently skipping using dblog for most things
class scanner(multiprocessing.Process):
    def __init__(self, device, devstring, channel, channels, verbose, gps, kill, name, json_queue):
        multiprocessing.Process.__init__(self)
        # TODO: We're assuming that the device can inject
        self.dev = device
        self.devstring = devstring
        self.channels = channels
        self.channel = channel
        self.verbose = verbose
        self.gps = gps
        self.kill = kill
        self.name = name
        self.json_queue = json_queue
        #self.sock = socket.socket()
        #self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #self.sock.connect(("127.0.0.1",8080))


    def run(self):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        print "Scanning with {}".format(self.devstring)

        staytime = 3
        beacon = "\x03\x08\x00\xff\xff\xff\xff\x07" # beacon frame
        beaconp1 = beacon[0:2]  # beacon part before seqnum field
        beaconp2 = beacon[3:]   # beacon part after seqnum field
        # TODO: Do we want to keep sequence numbers unique across devices?
        seqnum = 0              # seqnum to use (will cycle)

        import random

        while(1):
            #if(1):
                #if random.random() < 0.1:
                #    self.end()
                #    return

            if self.kill.is_set():
                print "{}: Kill event caught".format(self.devstring)
                self.end()
                return

            # Try to get the next channel, if there aren't any, sleep and try again
            # It shouldn't be empty unless there are more devices than channels
            try:
                self.channel.value = self.channels.get(False)
            except Queue.Empty():
                time.sleep(1)
                continue

            # Change channel
            try:
                self.dev.set_channel(self.channel.value)
            except Exception as e:
                print "%s: Failed to set channel to %d (%s)." % (self.devstring, self.channel.value, e)
                self.end()
                return

            # Send beacon
            if seqnum > 255:
                seqnum = 0
            beaconinj = beaconp1 + "%c" % seqnum + beaconp2
            if self.verbose:
                print "{}: Injecting a beacon request on channel {}".format(self.devstring, self.channel.value)
            try:
                self.dev.inject(beaconinj)
            except Exception, e:
                print "%s: Unable to inject packet (%s)." % (self.devstring,e)
                self.end()
                return

            # Listen for packets
            # TODO: Is there a better way to do this?
            endtime = time.time() + staytime

            try:
                while (endtime > time.time()):
                    # Get any packets (blocks for 100 usec)
                    packet = self.dev.pnext()
                    # TODO: Do we want the validcrc check?
                    if packet != None:# and packet['validcrc']:
                        if self.verbose:
                            print "{}: Found a frame on channel {}".format(self.devstring, self.channel.value)
                        self.capture(packet)
            except Exception as e:
                print "%s: Error in capturing packets (%s)." % (self.devstring,e)
                print traceback.format_exc()
                self.end()
                return

            self.dev.sniffer_off()

            # Add channel back to the queue
            self.channels.put(self.channel.value)

    # End and clean up the scanner
    # We don't add the channel back because we can't tell if
    # the process ended gracefully or an uncaught glib error
    def end(self):
        '''
        print "{}: Cleaning up".format(self.devstring)
        # TODO: is this all?
        try:
            self.dev.sniffer_off()
        except Exception as e:
            print "Sniffer off error: {}".format(e)
        try:
            self.dev.close()
        except Exception as e:
            print "Close error: {}".format(e)
        '''
        return

    # Captures packets
    # TODO: Make sure the first packet's metadata isn't too drifted
    # TODO: try/except for keyboardinterrupt
    def capture(self, packet, staytime=5):

        #for i in range(5):
        #    GPIO.output(self.led, True)
        #    time.sleep(0.1)
        #    GPIO.output(self.led, False)
        #    time.sleep(0.1)

        #self.sock.send("{} RECEIVING".format(self.name))

        #RPIO.output(17,True)
        #time.sleep(0.5)
        #RPIO.output(17,False)

        rf_freq_mhz = (self.channel.value - 10) * 5 + 2400
        packet_count = 1

        time_label = datetime.datetime.utcnow().strftime('%Y%m%d-%H%M')
        fname = 'zb_c%s_%s.pcap' % (self.channel.value, time_label) #fname is -w equiv
        pd = PcapDumper(DLT_IEEE802_15_4, fname, ppi=True)

        # TODO: make sure below
        #self.dev.sniffer_on() # The sniffer should already be on
        print "{}: capturing on channel {}".format(self.devstring, self.channel.value)

        # Loop and capture packets
        first = True
        endtime = time.time() + staytime
        while(endtime > time.time()):
            if first:
                # skip reading to record the packet we already got
                first = False
            else:
                # Blocks for 100 usec
                packet = self.dev.pnext()

            if packet != None:
                packet_count += 1
                try:
                    # Do the GPS if we can
                    # KB's hack is to use lat to see if all the data is there
                    if self.gps != None and 'lat' in self.gps:
                        print self.gps['lng'], self.gps['lat']

                        # If we have map data we need to write it to json
                        map_payload = (packet[0], (self.gps['lng'], self.gps['lat']))
                        self.json_queue.put(map_payload)

                        pd.pcap_dump(packet[0],
                                     freq_mhz=rf_freq_mhz, ant_dbm=packet['dbm'],
                                     location=(self.gps['lng'], self.gps['lat'], self.gps['alt']))
                    else:
                        map_payload = (packet[0], (1,2))
                        self.json_queue.put(map_payload)
                        print "NO GPS - not writing anything to JSON"
                        pd.pcap_dump(packet[0], freq_mhz=rf_freq_mhz,
                                          ant_dbm=packet['dbm'])
                except IOError as e:
                    # Below are all killerbee comments
                    #TODO replace this with code that ensures the captures exit before the manager
                    #     maybe have a shared memory int that is the number of currently running capture threads,
                    #     or use a shared state db, and only once all devices are marked free does the manager die
                    #if e.errno == 32: #broken pipe, likely from manager being shut down
                    #    continue
                    #else:
                    raise e
        # All done
        #self.dev.sniffer_off() # gets done later
        pd.close()
        print "{}: {} packets captured on channel {}".format(self.devstring, packet_count, self.channel.value)

# Takes a device id and returns the Zigbee device
# We make this its own function so we can time it
# and reset if it takes too long
# TODO: Better failing
def create_device(device_id, timeout=10, tries_limit=5):
    old_handler = signal.signal(signal.SIGALRM, timeoutHandler)
    tries = 0
    while(1):
        signal.alarm(10)
        try:
            kbdevice = KillerBee(device=device_id)
            break
        except TimeoutError:
            print "{}: Creation timeout (try={}/{})".format(device_id, tries, tries_limit)
            tries += 1
            if tries >= tries_limit:
                raise Exception("(%s): Failed to sync" % (device_id))
        finally:
            # TODO: what is this?
            signal.alarm(0)
    signal.signal(signal.SIGALRM, old_handler)
    return kbdevice


# http://stackoverflow.com/questions/492519/timeout-on-a-python-function-call
class TimeoutError(Exception):
    pass


def timeoutHandler(signum, frame):
    raise TimeoutError()


# TODO: how is GPS working?
def doScan(devices, currentGPS, verbose=False, dblog=False, agressive=False, staytime=2):
    timeout = 10
    tries_limit = 5

    #sock = socket.socket()
    #sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #sock.connect(("127.0.0.1", 8080))


    #RPIO.setup(17, RPIO.OUT)
    #RPIO.setup(18, RPIO.OUT)
    #RPIO.output(18,False)

    # Our pool/semaphor hybrid
    channels = multiprocessing.Queue()

    # Json mapper
    json_queue = multiprocessing.Queue()
    json_kill = multiprocessing.Event()
    map_json = MapJson(json_queue, json_kill)
    map_json.start()

    for i in range(11,26):
        channels.put(i)

    scanners = []
    names = ["KB1", "KB2", "KB3"]

    for device, name in zip(devices, names):
        print "Creating {}".format(device[0])
        kill_event = multiprocessing.Event()
        channel = multiprocessing.Value('i',0)

        kbdevice = create_device(device[0], timeout, tries_limit)

        scanner_proc = scanner(kbdevice, device[0], channel, channels,  verbose, currentGPS, kill_event, name, json_queue)
        s = {}
        s["dev"] = kbdevice
        s["devstring"] = device[0]
        s["channel"] = channel
        s["proc"] = scanner_proc
        s["kill"] = kill_event
        s["name"] = name

        scanners.append(s)

    for s in scanners:
        s["proc"].start()

    # TODO: better way to handle this
    # TODO: is it possible that we add the same channel twice?
    try:
        while 1:
            for i, s in enumerate(scanners):
                #RPIO.output(18,True)
                #time.sleep(0.5)
                #RPIO.output(18,False)

                #sock.send("HB ALIVE")

                # Wait on the join and then check if it's alive

                s["proc"].join(1)
                if not s["proc"].is_alive():
                    # TODO: does reusing this stuff work?
                    print "{}: Caught error. Respawning".format(s["devstring"])

                    # Add the cashed channel back to the list
                    channels.put(s["channel"].value)
                    s["channel"].value = 0 # don't need to do this

                    try:
                        s["dev"].sniffer_off()
                    except Exception as e:
                        print "{}: Sniffer off error ({})".format(s["devstring"],e)
                    try:
                        s["dev"].close()
                    except Exception as e:
                        print "{}: Close error ({})".format(s["devstring"],e)

                    # Resync the device and create another scanner
                    s["dev"] = create_device(s["devstring"], timeout, tries_limit)
                    s["proc"] = scanner(s["dev"], s["devstring"], s["channel"], channels, verbose, currentGPS, s["kill"], s["name"], json_queue)

                    # Add the the list first incase start throws an error so we can kill the new one
                    scanners[i] = s
                    scanners[i]["proc"].start()

    except KeyboardInterrupt:
        print "doScan() ended by KeyboardInterrupt"
    except Exception as e:
        print "doScan() caught non-Keyboard error: (%s)" % (e)
    finally:
        for s in scanners:
            s["kill"].set()
        json_kill.set()
        print "Setting map_json kill event"
        while not channels.empty():
            channels.get()
