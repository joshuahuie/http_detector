from scapy.all import IP
from scapy.all import sniff
from scapy.layers import http
import time
from threading import Thread

import signal
import sys
import os
import datetime
from average_time import average_time:


# Extracting all URLS


class http_detector:
    def __init__(self):
        self.requests_dict = {}
        #self.total_requests = 0
        self.divider = "-"


        self.two_minutes = average_time()
        self.global_time = average_time()


    def sniff_urls(self,packet):

        if packet.haslayer(http.HTTPRequest):
            http_layer = packet.getlayer(http.HTTPRequest)
            ip_layer = packet.getlayer(IP)
            #print '\n{0[src]} - {1[Method]} - http://{1[Host]}{1[Path]}'.format(ip_layer.fields, http_layer.fields)
            #print '\n{0[src]} - {1[Method]} - http://{1[Host]}{1[Path]}'.format(ip_layer.fields, http_layer.fields)
            #print "\n" + "http://" + http_layer.fields["Host"] + http_layer.fields["Path"] # the host name you're visiting
            

            http_link = "http://{[Host]}{[Path]}".format(http_layer.fields,http_layer.fields)
            
            self.insert(http_link,self.requests_dict)
            #self.total_requests += 1
            self.global_time.add_requests(1)
            self.two_minutes.add_requests(1)

    def insert(self,link,current_dict):
        if current_dict.get(link,None) == None:
            current_dict[link] = 1
        else:
            current_dict[link] += 1

    #def high_traffic_check(self):


    def get_section(self,max_url):

        if max_url:
            parsed_path = max_url.split("/")
            length = len(parsed_path)
            
            if length <= 3:
                return max_url
            else:
                if parsed_path[3] == "":
                    return max_url
                else:
                    return  "http://{}/{}".format(parsed_path[2],parsed_path[3])            



    def get_max(self):
        if self.requests_dict:
            return max(self.requests_dict)
        else:
            return None

    def interesting_stats(self):
        print(self.divider * 15 + "Summary Statistics" + self.divider * 25)
        #print("\nTotal Number of HTTP requests so far: {}".format(self.total_requests))
        
        
        print("\n\n")
        
        if self.divider == "-":
            self.divider = "="
        else:
            self.divider = "-"

        #rate of requests per min

    def print_max_links(self,max_key):
        max_count = self.requests_dict[max_key]

        for key,value in self.requests_dict.items():
            if value == max_count:
                one_section = self.get_section(key)
                print("\nWebsite with the most hits: {}".format(key)) 
                print("Section of the website: {}".format(one_section))

    def start_sniffing(self):
        timeout = time.time() + 60*2 
        while True:
            if time.time() > timeout:
                if self.two_minutes > self.global_time:
                    # PRINT
                else:
                    # PRINT
                self.two_minutes.clear()
            
            sniff(filter='tcp', prn=new.sniff_urls, timeout=10)
            self.global_time.add_seconds(10)
            self.two_minutes.add_seconds(10)
            
            max_appearance = self.get_max()
            print(datetime.datetime.now())
            print(self.divider * 15 + "HTTP Info" + self.divider * 34)
            
            if max_appearance:
                self.print_max_links(max_appearance)
            else:
                print("\nThere is no current website with max hits")

            print("\n")
            
            self.interesting_stats()
            self.requests_dict.clear()

def signal_handler(sig, frame):
    print("\nStopped Program Successfully.")
    sys.exit(1)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    new = http_detector()
    new.start_sniffing()

    """
    try:
        new = http_detector()
        thread = Thread(target = new.start_sniffing)
        thread.start()
    except KeyboardInterrupt:
        sys.exit(1)
    """








#sniff(filter='tcp', prn=new.sniff_urls, timeout=10)
#while True:
    #sniff(filter='tcp', prn=sniff_urls, timeout=10)
    #new_dict = {}

"""
def stopwatch():
    now = time.time()
    future = now + 3
    while True:
        if now < future:
            print "we're not there yet"
        elif now == future:
            break
            print "hey babe" * 3
            future = now + 3
        now = time.time()
"""
"""
starttime=time.time()
while True:
  time.sleep(10.0 - ((time.time() - starttime) % 10.0))
  print "hey babe"
"""

"""
def print_forever():
    while True:
        print("hi")
        print("bye")

def sleep_ten():
    time.sleep(10)
"""
"""
t1 = threading.Thread(target=print_forever)
t2 = threading.Thread(target=sleep_ten)

t1.start()
#t2.start()

t1.join(10)
#t2.join()
"""


#function that monitors all traffic and builds a dict of counts
#at ten seconds pause and extract the most, then continue


## global dictionary with counts
#stopwatch()
# Start sniffing the network.
#sniff(filter='tcp', prn=sniff_urls, timeout=10)
#print("HEY BABE")
# DO constant work
# DO a timer until 10 seconds is reached