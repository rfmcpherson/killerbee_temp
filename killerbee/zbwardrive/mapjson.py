#!/usr/bin/env python

import json
import multiprocessing
import signal
import time
import os
from killerbee import *

class MapJson(multiprocessing.Process):
    def __init__(self, queue, kill_event):
        multiprocessing.Process.__init__(self)
        if not os.path.exists("./mapjson"):
            print "MapJson: Creating directory to store results"
            os.makedirs("./mapjson")
        else:
            print "MapJson: I see you already have this directory, very nice."
        self.queue = queue
        self.kill = kill_event
        self.feature_collection = self.build_feature_collection()
        self.dot15decoder = Dot154PacketParser()
        self.zbdecoder = ZigBeeNWKPacketParser()
        self.zbapsdecoder = ZigBeeAPSPacketParser()

    def run(self):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        start_time = time.time()
        while 1: # tee hee
            if self.kill.is_set():
                print "MapJson: Kill event caught ending now"
                self.end()
                return
            # Grab that packet
            new_time = time.time()
            if (new_time - start_time >= 30) and (not self.feature_collection["features"]):
                print "MapJson: Capture timeout reached, writing out to file now"
                self.write_json()
                self.feature_collection = self.build_feature_collection()
                start_time = time.time()
            try:
                payload = self.queue.get(timeout=5)
            except:
                continue
            # Add it to the collection
            print "Attempting to decode the packet"
            self.decode_packet(payload[0])
            print "MapJson: Adding new packet to the collection"
            self.feature_collection["features"].append(self.build_feature(payload))

    def end(self):
        while 1:
            try:
                payload = self.queue.get(timeout=5)
                print "MapJson: Adding remaining packet to the collection before exiting"
                self.feature_collection["features"].append(self.build_feature(payload))
            except:
                self.write_json()
                break

    #Dot15
        #FCF | Seq# | DPAN | DA | SPAN | SA | [Beacon Data] | PHY Payload
    #Beacon Data
        #Superframe Spec | GTS Fields | Pending Addr Counts | Proto ID | Stack Profile/Profile Version | Device Capabilities | Ext PAN ID | TX Offset | Update ID
    #NWK
        #Frame Control | DA | SA | Radius | Seq # | Dst IEEE Address | Src IEEE Address | MCast Ctrl | Src Route Subframe | Payload
    #APS
        #Frame Control | Dst Endpoint | Group Address | Cluster Identifier | Profile Identifier | Source Endpoint | APS Counter | Payload
    def decode_packet(self, packet):
        pass


    def build_feature_collection(self):
        feature_collection = {}
        feature_collection["type"] = "FeatureCollection"
        feature_collection["features"] = []
        return feature_collection


    def build_feature(self, payload):
        packet = payload[0]
        gps = payload[1]
        # Feature Type
        new_feature = {}
        new_feature["type"] = "Feature"
        # Feature Properties
        new_feature["properties"] = {}
        new_feature["properties"]["id"] = "Placeholder"
        new_feature["properties"]["title"] = "Zigbee Packet %s" % packet
        new_feature["properties"]["description"] = "Placeholder"
        new_feature["properties"]["marker-size"] = "small"
        new_feature["properties"]["marker-color"] = "#1087bf"
        new_feature["properties"]["marker-symbol"] = "z"
        # Feature Geometry
        new_feature["geometry"] = {}
        new_feature["geometry"]["coordinates"] = [gps[0], gps[1]]
        new_feature["geometry"]["type"]  = "Point"
        # Feature ID
        new_feature["id"] = "Placeholder" # Figure out how to populate this
        return new_feature

    def write_json(self):
        with open("./mapjson/map-json-%s.json" % time.strftime("%Y%m%d-%H%M%S"), 'w') as output:
            json.dump(self.feature_collection, output)
