#!/usr/bin/env python

# ZBWarDrive
# rmspeers 2010-13
# ZigBee/802.15.4 WarDriving Platform

from time import sleep
from usb import USBError

from killerbee import KillerBee, kbutils
from db import ZBScanDB
from scanning import doScan

GPS_FREQUENCY=3 #in seconds

# GPS Poller
def gpsdPoller(currentGPS):
    '''
    @type currentGPS multiprocessing.Manager dict manager
    @arg currentGPS store relavent pieces of up-to-date GPS info
    '''
    import killerbee.zbwardrive.gps
    import os
    print os.path.dirname(killerbee.zbwardrive.gps.__file__)
    gpsd = killerbee.zbwardrive.gps.gps()
    #print "type: {}".format(type(gpsd))
    #methods = [method for method in dir(gpsd)]
    #print "\n".join(methods)
    gpsd.poll()
    gpsd.stream()

    try:
        while True:
            gpsd.poll()
            if gpsd.fix.mode > 1: #1=NO_FIX, 2=FIX, 3=DGPS_FIX
                lat = gpsd.fix.latitude
                lng = gpsd.fix.longitude
                alt = gpsd.fix.altitude
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


    ignore = "/dev/ttyUSB0"
    print ignore

    devices = kbutils.devlist(gps=ignore, include=include)

    for kbdev in devices:
        print 'Found device at %s: \'%s\'' % (kbdev[0], kbdev[1])
        
    kb.close()
    doScan(devices, currentGPS, verbose=verbose, dblog=dblog, agressive=agressive)
    return True
