#!/usr/bin/env python

# ZBWarDrive
# rmspeers 2010-13
# ZigBee/802.15.4 WarDriving Platform

from time import sleep
from usb import USBError
from subprocess import call

from killerbee import KillerBee, kbutils
from db import ZBScanDB
from scanning import doScan

GPS_FREQUENCY=3 #in seconds

def googLat(lat):
    return lat > -180.00000005 and lat < 180.00000005

def goodLng(lng):
    return goodLat(lng)

def goodAlt(alt):
    alt > -180000.00005 and alt < 180000.00005

# GPS Poller
def gpsdPoller(currentGPS):
    '''
    @type currentGPS multiprocessing.Manager dict manager
    @arg currentGPS store relavent pieces of up-to-date GPS info
    '''
    import killerbee.zbwardrive.gps
    import socket

    gpsd = killerbee.zbwardrive.gps.gps()
    gpsd.poll()
    gpsd.stream()

    #sock = socket.socket()
    #sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #sock.connect(("127.0.0.1",8080))

    try:
        while True:
            gpsd.poll()
            if gpsd.fix.mode > 1: #1=NO_FIX, 2=FIX, 3=DGPS_FIX
                lat = gpsd.fix.latitude
                lng = gpsd.fix.longitude
                alt = gpsd.fix.altitude
                #if alt:
                #    sock.send("GPS FULL")
                #else:
                #    sock.send("GPS PARTIAL")
                #print 'latitude    ' , lat
                #print 'longitude   ' , lng
                #TODO do we want to use the GPS time in any way?
                #print 'time utc    ' , gpsd.utc,' + ', gpsd.fix.time
                #print 'altitude (m)' , alt
                currentGPS['lat'] = lat
                currentGPS['lng'] = lng
                currentGPS['alt'] = alt
            else:
                print "Waiting for a GPS fix."
                #TODO timeout lat/lng/alt values if too old...?
            sleep(GPS_FREQUENCY)
    except KeyboardInterrupt:
        print "Got KeyboardInterrupt in gpsdPoller, returning."
        return

# startScan
# Detects attached interfaces
# Initiates scanning using doScan()
def startScan(currentGPS, verbose=False, dblog=False, agressive=False, include=[], ignore=None):
    print "In startScan()"

    import time

    try:
        kb = KillerBee()
    except USBError, e:
        if e.args[0].find('Operation not permitted') >= 0:
            print 'Error: Permissions error, try running using sudo.'
        else:
            print 'Error: USBError:', e
        return False
    except Exception, e:
        print 'Error: Issue starting KillerBee instance:', e
        return False

    if verbose:
        print "gps: {}".format(ignore)

    devices = kbutils.devlist(gps=ignore, include=include)

    for kbdev in devices:
        print 'Found device at %s: \'%s\'' % (kbdev[0], kbdev[1])
        
    kb.close()
    doScan(devices, currentGPS, verbose=verbose, dblog=dblog, agressive=agressive)
    return True
