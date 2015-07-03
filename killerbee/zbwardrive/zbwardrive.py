#!/usr/bin/env python

# ZBWarDrive
# rmspeers 2010-13
# ZigBee/802.15.4 WarDriving Platform


import logging
from subprocess import call
from time import sleep
from usb import USBError

from db import ZBScanDB
from killerbee import KillerBee, kbutils
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

    try:
        while True:
            gpsd.poll()
            if gpsd.fix.mode > 1: #1=NO_FIX, 2=FIX, 3=DGPS_FIX
                lat = gpsd.fix.latitude
                lng = gpsd.fix.longitude
                alt = gpsd.fix.altitude
                #print 'time utc    ' , gpsd.utc,' + ', gpsd.fix.time
                currentGPS['lat'] = lat
                currentGPS['lng'] = lng
                currentGPS['alt'] = alt
                log_message = "GPS: {}, {}, {}".format(lat, lng, alt)
                logging.debug(log_message)
            else:
                log_message = "No GPS fix"
                logging.info(log_message)
                #TODO timeout lat/lng/alt values if too old...?
            sleep(GPS_FREQUENCY)
    except KeyboardInterrupt:
        log_message = "Got KeyboardInterrupt in gpsdPoller, returning." 
        print log_message
        logging.debug(log_message)
        return

# startScan
# Detects attached interfaces
# Initiates scanning using doScan()
def startScan(currentGPS, verbose=False, dblog=False, agressive=False,
              include=[], ignore=None, output='.'):
    logging.debug("In startScan()")

    try:
        kb = KillerBee()
    except USBError, e:
        if e.args[0].find('Operation not permitted') >= 0:
            log_message = 'Error: Permissions error, try running using sudo.'
            logging.error(log_message)
            print log_message
        else:
            log_message = 'Error: USBError: {}'.format(e)
            logging.error(log_message)
            print log_message
        return False
    except Exception, e:
        log_message = 'Error: Issue starting KillerBee instance: {}'.format(e)
        logging.error(log_message)
        print log_message
        return False

    log_message = "gps: {}".format(ignore)
    if verbose:
        print log_message
    logging.info(log_message)

    devices = kbutils.devlist(gps=ignore, include=include)

    for kbdev in devices:
        log_message = 'Found device at %s: \'%s\'' % (kbdev[0], kbdev[1])
        logging.info(log_message)
        if verbose:
            print log_message

    log_message = "Sending output to {}".format(output)
    if verbose:
        print log_message
    logging.info(log_message)

    kb.close()
    doScan(devices, currentGPS, verbose=verbose, dblog=dblog, agressive=agressive, output=output)
    return True
