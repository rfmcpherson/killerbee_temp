import json
import multiprocessing
import signal
import time
import os
import uuid
from killerbee import *

# List of 802.15.4 fields that may or may not be in the packet
dot15fields = ["FCF",
               "Sequence Number",
               "Destination PAN",
               "Destination Address",
               "Source PAN",
               "Source Address",
               "Beacon Data",
               "PHY Payload"]

# List of beacon fields that may or may not be in the packet
beaconfields = ["Superframe Spec",
                "GTS Fields",
                "Pending Address Count",
                "Proto ID",
                "Stack Profile/Profile Version",
                "Device Capabilities",
                "Extended PAN ID",
                "TX Offset",
                "Update ID"]

# List of ZigBee Network layer fields that may or may not be in the packet
zbnwkfields = ["FCF",
               "Destination Address",
               "Source Address",
               "Radius",
               "Sequence Number",
               "Destination IEEE Address",
               "Source IEEE Address",
               "MCast Control",
               "Source Route Subframe",
               "Network Payload"]

# List of ZigBee APS layer fields that may or may not be in the packet
zbapsfields = ["FCF",
               "Destination Endpoint",
               "Group Address",
               "Cluster Identifier",
               "Profile Identifier",
               "Source Endpoint",
               "APS Counter",
               "APS Payload"]

def bytes2str(b):
    return "".join("{:02x}".format(ord(c)) for c in b)

class MapJson(multiprocessing.Process):
    # Sets up the multiprocessing parameters needed to
    # Asynchronously log packets as JSON data
    #
    # Parameters:
    # queue      - the multiprocessing.Queue that will be used to collect packets
    # kill_event - the even to shut down the process
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
        self.zbnwkdecoder = ZigBeeNWKPacketParser()
        self.zbapsdecoder = ZigBeeAPSPacketParser()

    # Main function that the new process will execute
    # It will loop until the kill signal is set attempting
    # to read packets from the queue.  If one is received,
    # it will attempt to identify all fields present in the
    # packet and then append the resulting data to the
    # feature_collection.
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
            if (new_time - start_time >= 10) and self.feature_collection["features"]:
                print "MapJson: Capture timeout reached, writing out to file now"
                self.write_json()
                self.feature_collection = self.build_feature_collection()
                start_time = time.time()
            try:
                payload = self.queue.get(timeout=5)
            except:
                continue
            # Add it to the collection
            decoded_packet = self.decode_packet(payload[0])
            gps_coords = payload[1]
            print "MapJson: Adding new packet to the collection"
            self.feature_collection["features"].append(self.build_feature(decoded_packet, gps_coords))

    # This will attempt to process any packets that may still be
    # in the queue when the kill event has ben caught.  It will
    # then write the feature_collection out to the JSON file
    def end(self):
        while 1:
            try:
                payload = self.queue.get(timeout=5)
                print "MapJson: Adding remaining packet to the collection before exiting"
                self.feature_collection["features"].append(self.build_feature(payload))
            except:
                self.write_json()
                break

    # Does the heavy lifting of the packet decoding.
    #
    # Parameters:
    # field_list    - one of the four main lists of fields.
    # packet_fields - the result of a pktchop() on the captured packet
    # Returns:
    # A hash containing the names of the present fields as keys and their value as values
    def detect_fields(self, field_list, packet_fields):
        result_hash = {}
        for field, pkt_field in zip(field_list, packet_fields):
            result_hash[field] = pkt_field
        return result_hash

    # This function will attempt to identify all fields available in the packet
    #
    # Parameters:
    # packet - the captured packet that needs to be decoded
    # Returns:
    # A hash containing all of the decoded fields
    def decode_packet(self, packet):
        decoded_packet = {}
        decoded_packet["Dot15d4 Fields"] = self.detect_fields(dot15fields, self.dot15decoder.pktchop(packet))
        if decoded_packet["Dot15d4 Fields"]["Beacon Data"]:
            decoded_packet["Beacon Fields"] = self.detect_fields(beaconfields, decoded_packet["Dot15d4 Fields"]["Beacon Data"])
        else:
            decoded_packet["Beacon Fields"] = {}
            for key in beaconfields:
                decoded_packet["Beacon Fields"][key] = None # i hate this
        decoded_packet["ZigBee NWK Fields"] = self.detect_fields(zbnwkfields, self.zbnwkdecoder.pktchop(packet))
        decoded_packet["ZigBee APS Fields"] = self.detect_fields(zbapsfields, self.zbapsdecoder.pktchop(packet))
        return decoded_packet

    # Sets up the top level feature collection for JSON mapping
    # All packets will be logged as "features" in this object
    def build_feature_collection(self):
        feature_collection = {}
        feature_collection["type"] = "FeatureCollection"
        feature_collection["features"] = []
        return feature_collection

    # Builds individual features to be used in the JSON mapping
    # Each feature specifies its GPS coordinates along with some
    # visual properties.  It also contains the decoded packet data.
    def build_feature(self, decoded_packet, gps_coords):
        """
        Title: 
        ZigBee Beacon <span class="panid"> 0x7F39</span>

        Description:
        <hr>
        Ext PANID: ee:3d:30:f2:0f:1f:52:13 <br>
        Stack Profile: ZigBee Enterprise <br>
        Stack Version: ZigBee 2006/2007 <br>
        Channel: 20 <br>
        Security Enabled: <strong style="color:red">False</strong> <br><br>
        <button>Packet capture analysis</button>

        Id: 
        UUID
        """

        uid = str(uuid.uuid4()) # hex uuid in the form: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

        if decoded_packet["ZigBee NWK Fields"]:
            protocol = "Zigbee"
        else:
            protocol = "802.15.4"

        if decoded_packet["Dot15d4 Fields"]["Source PAN"]:
            source_panid = bytes2str(decoded_packet["Dot15d4 Fields"]["Source PAN"])
        else:
            source_panid = "Not Identified"

        if decoded_packet["Beacon Fields"]["Extended PAN ID"]:
            ext_panid = bytes2str(decoded_packet["Beacon Fields"]["Extended PAN ID"])
        else:
            ext_panid = "Not Identified"

        if decoded_packet["Dot15d4 Fields"]["Destination PAN"]:
            dest_panid = bytes2str(decoded_packet["Dot15d4 Fields"]["Destination PAN"])
        else:
            dest_panid = "Not Identified"

        '''
        if decoded_packet["ZigBee APS Fields"]["Cluster Identifier"]:
            cluster_id = decoded_packet["ZigBee APS Fields"]["Cluster Identifier"]
        else:
            cluster_id = "Not Identified"
        '''

        title = 'ZigBee Beacon <span class="panid"> {}</span>'.format(source_panid)

        description = '<hr>\n'
        description += 'Protocol: {}<br>\n'.format(protocol)
        description += 'Source PANID: {}<br>\n'.format(source_panid)
        description += 'Extended Source PANID: {}<br>\n'.format(ext_panid)
        description += 'Destination PANID: {}<br><br>\n'.format(dest_panid)
        description += '<button>Packet capture analysis</button>'

        # Feature Type
        new_feature = {}
        new_feature["type"] = "Feature"
        # Feature Properties
        new_feature["properties"] = {}
        new_feature["properties"]["id"] = uid
        new_feature["properties"]["title"] = title
        new_feature["properties"]["description"] = description
        new_feature["properties"]["marker-size"] = "small"
        new_feature["properties"]["marker-color"] = "#1087bf"
        new_feature["properties"]["marker-symbol"] = "z"
        # Feature Geometry
        new_feature["geometry"] = {}
        new_feature["geometry"]["coordinates"] = [gps_coords[0], gps_coords[1]]
        new_feature["geometry"]["type"]  = "Point"
        # Feature ID
        new_feature["id"] = uid
        return new_feature

    # Write the current state of the feature_collection out to a json file
    # that is named according to the current time.
    def write_json(self):
        with open("./mapjson/map-json-%s.json" % time.strftime("%Y%m%d-%H%M%S"), 'w') as output:
            json.dump(self.feature_collection, output)
