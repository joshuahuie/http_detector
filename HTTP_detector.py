from scapy.all import IP
from scapy.all import sniff
from scapy.layers import http
from datetime import datetime
from average_time import average_time
from threading import Thread

import time
import signal
import sys
import os



class http_detector:
    def __init__(self):
        self.requests_dict = {}
        self.divider = "-"

        self.two_minutes = average_time()
        self.global_time = average_time()


    def sniff_start(self,packet):
        if packet.haslayer(http.HTTPRequest):
            http_layer = packet.getlayer(http.HTTPRequest)
            ip_layer = packet.getlayer(IP)
            http_link = "http://{[Host]}{[Path]}".format(http_layer.fields,http_layer.fields)
            
            self.insert(http_link,self.requests_dict)
            self.global_time.add_requests(1)
            self.two_minutes.add_requests(1)



    def insert(self,link,current_dict):
        if current_dict.get(link,None) == None:
            current_dict[link] = 1
        else:
            current_dict[link] += 1


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


    def switch_dividers(self):
        if self.divider == "-":
            self.divider = "="
        else:
            self.divider = "-"


    def interesting_stats(self, packets):
        print(self.divider * 100)
        print("Summary Statistics:")
        print("\nTotal Number of HTTP requests so far: {}".format(self.global_time.return_requests()))
        
        print("Number of packets detected in 10 seconds: " + str(len(packets)))
        print("\n\n")
        
        self.switch_dividers()


    def print_max_links(self,max_key):
        max_count = self.requests_dict[max_key]

        for key,value in self.requests_dict.items():
            if value == max_count:
                one_section = self.get_section(key)
                print("\nWebsite with the most hits: {}".format(key)) 
                print("Section of the website: {}".format(one_section))

    def return_traffic_type(self,converted_time):
        if self.two_minutes > self.global_time:
            return "High traffic generated an alert - hits = {value}, triggered at {time}\n".format(value=self.two_minutes.return_requests(),time=converted_time)
        elif self.two_minutes < self.global_time:
            return "Low traffic generated an alert - hits = {value}, triggered at {time}\n".format(value=self.two_minutes.return_requests(),time=converted_time)


    def start_sniffing(self):
        timeout = time.time() + 60*2

        while True:
            current_time = time.time()
            converted_time = str(datetime.fromtimestamp(current_time).strftime("%A, %B %d, %Y %I:%M:%S"))
            
            if current_time > timeout: # if block determines if there's high traffic or low traffic
                traffic_str = self.return_traffic_type(converted_time)
                if traffic_str != None:
                    print(traffic_str)

                self.two_minutes.clear()
                timeout = time.time() + 60*2 
        
    
            packets = sniff(filter='tcp', prn=new.sniff_start, timeout=10) #Block sniffs HTTP traffic and updates requests / seconds
            self.global_time.add_seconds(10)
            self.two_minutes.add_seconds(10)
            

            max_appearance = self.get_max()
            print("Current Time: {}".format(datetime.now()))
            print(self.divider * 100)
            print("HTTP Info:")
            

            if max_appearance:
                self.print_max_links(max_appearance)
            else:
                print("\nThere is no current website with max hits\n")
            

            self.interesting_stats(packets)
            self.requests_dict.clear()


def signal_handler(sig, frame):
    print("\nStopped Program Successfully.")
    sys.exit(1)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    new = http_detector()
    new.start_sniffing()