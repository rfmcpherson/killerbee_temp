#!/usr/bin/env python

import datetime
import multiprocessing
import Queue
import signal
import time
import traceback
import logging

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
    log_message = 'This Requires Scapy To Be Installed.'
    print log_message
    logging.warning(log_message)
    from sys import exit
    exit(-1)

#TODO set iteration min to a sensical parameter
MIN_ITERATIONS_AGRESSIVE = 0


# TODO: we're currently skipping using dblog for most things
class scanner(multiprocessing.Process):
    def __init__(self, device, devstring, channel, channels, verbose, gps, kill, json_queue):
        multiprocessing.Process.__init__(self)
        # TODO: We're assuming that the device can inject
        self.dev = device
        self.devstring = devstring
        self.channels = channels
        self.channel = channel
        self.verbose = verbose
        self.gps = gps
        self.kill = kill
        #self.name = name
        self.json_queue = json_queue
        #self.sock = socket.socket()
        #self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #self.sock.connect(("127.0.0.1",8080))


    def run(self):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        log_message = "Scanning with {}".format(self.devstring)
        if self.verbose:
            print log_message
        logging.debug(log_message)

        staytime = 3
        beacon = "\x03\x08\x00\xff\xff\xff\xff\x07" # beacon frame
        beaconp1 = beacon[0:2]  # beacon part before seqnum field
        beaconp2 = beacon[3:]   # beacon part after seqnum field
        # TODO: Do we want to keep sequence numbers unique across devices?
        seqnum = 0              # seqnum to use (will cycle)

        while(1):
            #if(1):
                #if random.random() < 0.1:
                #    self.end()
                #    return

            if self.kill.is_set():
                log_message = "{}: Kill event caught".format(self.devstring)
                if self.verbose:
                    print log_message
                logging.debug(log_message)
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
                log_message = "%s: Failed to set channel to %d (%s)." % (self.devstring, self.channel.value, e)
                if self.verbose: 
                    print log_message
                logging.warning(log_message)
                self.end()
                return

            # Send beacon
            if seqnum > 255:
                seqnum = 0
            beaconinj = beaconp1 + "%c" % seqnum + beaconp2
            log_message = "{}: Injecting a beacon request on channel {}".format(self.devstring, self.channel.value) 
            if self.verbose:
                print log_message
            logging.debug(log_message)
            try:
                self.dev.inject(beaconinj)
            except Exception, e:
                log_message = "%s: Unable to inject packet (%s)." % (self.devstring,e)
                if self.verbose:
                    print log_message
                logging.warning(log_message)
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
                        log_message = "{}: Found a frame on channel {}".format(self.devstring, self.channel.value)
                        if self.verbose:
                            print log_message
                        logging.debug(log_message)
                        self.capture(packet)
            except Exception as e:
                log_message = "%s: Error in capturing packets (%s)." % (self.devstring,e)
                if self.verbose:
                    print log_message
                    print traceback.format_exc()
                logging.warning(log_message)
                logging.warning(traceback.format_exc())
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
        log_message = "{}: capturing on channel {}".format(self.devstring, self.channel.value)
        if self.verbose:
            print log_message
        logging.debug(log_message)

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
                        # If we have map data we need to write it to json
                        map_payload = (packet[0], (self.gps['lng'], self.gps['lat']))
                        #map_payload = (packet[0], (90, 90))
                        self.json_queue.put(map_payload)

                        pd.pcap_dump(packet[0],
                                     freq_mhz=rf_freq_mhz, ant_dbm=packet['dbm'],
                                     location=(self.gps['lng'], self.gps['lat'], self.gps['alt']))
                    else:
                        log_message = "NO GPS - not writing anything to JSON"
                        if self.verbose:
                            print log_message
                        logging.warning(log_message)
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
        log_message =  "{}: {} packets captured on channel {}".format(self.devstring, packet_count, self.channel.value)
        if self.verbose:
            print log_message
        logging.debug(log_message)

# Takes a device id and returns the Zigbee device
# We make this its own function so we can time it
# and reset if it takes too long
# TODO: Better failing
def create_device(device_id, verbose=False, timeout=10, tries_limit=5):
    old_handler = signal.signal(signal.SIGALRM, timeoutHandler)
    tries = 0
    while(1):
        signal.alarm(10)
        try:
            kbdevice = KillerBee(device=device_id)
            break
        except TimeoutError:
            log_message = "{}: Creation timeout (try={}/{})".format(device_id, tries, tries_limit)
            if verbose:
                print log_message
            logging.warning(log_message)
            tries += 1
            if tries >= tries_limit:
                log_message = "(%s): Failed to sync" % (device_id)
                if verbose:
                    print log_message
                logging.warning(log_message)
                raise Exception(log_message)
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
    map_json = MapJson(queue=json_queue, kill_event=json_kill, verbose=verbose)
    map_json.start()

    for i in range(11,26):
        channels.put(i)

    scanners = []
    #names = ["KB1", "KB2", "KB3"]

    for device in devices:
        log_message =  "Creating {}".format(device[0])
        if verbose:
            print log_message
        logging.debug(log_message)
        kill_event = multiprocessing.Event()
        channel = multiprocessing.Value('i',0)

        kbdevice = create_device(device[0], verbose=verbose, timeout=timeout, tries_limit=tries_limit)

        scanner_proc = scanner(kbdevice, device[0], channel, channels,  verbose, currentGPS, kill_event, json_queue)
        s = {}
        s["dev"] = kbdevice
        s["devstring"] = device[0]
        s["channel"] = channel
        s["proc"] = scanner_proc
        s["kill"] = kill_event
        #s["name"] = name

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
                    log_message = "{}: Caught error. Respawning".format(s["devstring"])
                    if verbose:
                        print log_message
                    logging.warning(log_message)

                    # Add the cashed channel back to the list
                    channels.put(s["channel"].value)
                    s["channel"].value = 0 # don't need to do this

                    try:
                        s["dev"].sniffer_off()
                    except Exception as e:
                        log_message = "{}: Sniffer off error ({})".format(s["devstring"],e)
                        if verbose:
                            print log_message
                        logging.warning(log_message)
                    try:
                        s["dev"].close()
                    except Exception as e:
                        log_message = "{}: Close error ({})".format(s["devstring"],e)
                        if verbose:
                            print log_message
                        logging.warning(log_message)

                    # Resync the device and create another scanner
                    s["dev"] = create_device(s["devstring"], verbose=verbose, timeout=timeout, tries_limit=tries_limit)
                    s["proc"] = scanner(s["dev"], s["devstring"], s["channel"], channels, verbose, currentGPS, s["kill"], json_queue)

                    # Add the the list first incase start throws an error so we can kill the new one
                    scanners[i] = s
                    scanners[i]["proc"].start()

    except KeyboardInterrupt:
        log_message = "doScan() ended by KeyboardInterrupt"
        if verbose:
            print log_message
        logging.info(log_message)
    except Exception as e:
        log_message = "doScan() caught non-Keyboard error: (%s)" % (e)
        if verbose:
            print log_message
        logging.warning(log_message)
    finally:
        for s in scanners:
            s["kill"].set()
        json_kill.set()
        log_message = "Setting map_json kill event"
        if verbose:
            print log_message
        logging.info(log_message)
        while not channels.empty():
            channels.get()
