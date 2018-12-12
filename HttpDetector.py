from scapy.all import IP
from scapy.all import sniff
from scapy.layers import http
from datetime import datetime
from AverageTime import AverageTime
from threading import Thread

import time
import signal
import sys
import os



class HttpDetector:
    def __init__(self):
        """Initalizes the class"""

        self.requests_dict = {}
        self.divider = "-" # Character used for dividing text
        self.alerts = []
    

        self.two_minutes = AverageTime()
        self.global_time = AverageTime()


    def sniff_start(self,packet):
        """
        Function used with scapy's sniff. 
        This function adds the http links into self.requests_dict and adds to request counts
        """

        if packet.haslayer(http.HTTPRequest):
            http_layer = packet.getlayer(http.HTTPRequest)
            ip_layer = packet.getlayer(IP)
            http_link = "http://{[Host]}{[Path]}".format(http_layer.fields,http_layer.fields)
            
            self.insert(http_link,self.requests_dict,1)
            self.global_time.add_requests(1)
            self.two_minutes.add_requests(1)


    def insert(self,link,current_dict,amount):
        """
        Helper function to insert into dictionary for counting
        """

        if current_dict.get(link,None) == None:
            current_dict[link] = amount
        else:
            current_dict[link] += amount


    def find_website_most_hits(self):
        """ 
        Based on the requests dictionary will return the base url with the most requests 
        and how many times it appeared
        """

        dict_of_requests = {} 
        
        for key in self.requests_dict.keys(): # for each link, get the base url, if it exists add appropriate count
            base_url = self.get_base_add(key)
            self.insert(base_url,dict_of_requests,self.requests_dict[key])

        if dict_of_requests:
            url_most_appearances = max(dict_of_requests.iterkeys(), key=(lambda key: dict_of_requests[key]))
            return url_most_appearances,dict_of_requests[url_most_appearances] #the base url with most appearances and it's count
        
        return None


    def get_base_add(self,url):
        """ Gets the host name """

        if url:
            parsed_path = url.split("/")
            return "http://{}".format(parsed_path[2])  
        return None



    def get_section(self,max_url):
        """Given a URL, splits it and returns the url with one section"""

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
        """Returns the link with the most hits"""

        if self.requests_dict:
            return max(self.requests_dict.iterkeys(), key=(lambda key: self.requests_dict[key]))
        else:
            return None


    def switch_dividers(self):
        if self.divider == "-":
            self.divider = "="
        else:
            self.divider = "-"


    def interesting_stats(self, packets):
        """ Prints interesting stats: num of HTTP requests and num of detected packets"""

        print("Summary Statistics:")
        print("\nTotal Number of HTTP requests so far: {}".format(self.global_time.return_requests()))
        
        print("Number of packets detected in 10 seconds: " + str(len(packets)))
        print(self.divider * 100)
        print("\n")
        


    def print_max_links(self,base_site):
        """ Print top three or less websites based on the base website"""

        dict_base_sections = {}

        for key,value in self.requests_dict.items():
            if base_site in key: #if link includes base site insert it
                link_with_section = self.get_section(key) #Get the link with one section
                self.insert(link_with_section,dict_base_sections,self.requests_dict[key]) #Insert it 

        max_links = sorted(dict_base_sections, key=dict_base_sections.get, reverse=True)[:3] #Find top three or less base sections
        
        for link in max_links: 
            print("-Section: {}".format(link))
            print("-Hits: {}".format(dict_base_sections[link]))



    def return_traffic_type(self,converted_time):
        """Returns whether or not there is high traffic or low traffic"""
        if self.two_minutes > self.global_time:
            return "High traffic generated an alert - hits = {value}, triggered at {time}\n".format(value=self.two_minutes.return_requests(),time=converted_time)
        elif self.two_minutes < self.global_time:
            return "Low traffic generated an alert - hits = {value}, triggered at {time}\n".format(value=self.two_minutes.return_requests(),time=converted_time)
        
        return None

    def print_previous_alerts(self):
        """If there are previous alerts, function will print them from self.alerts"""
        if self.alerts:
            print("Previous Alerts:")
            for alert in self.alerts:
                print(alert)


    def start_sniffing(self):
        """Main function in charge of printing diagonstic information and updating requests/seconds"""
 
        print("Program has started.\n")
        timeout = time.time() + 60*2 # Two minutes ahead

        while True:
            self.print_previous_alerts()
            current_time = time.time()
            converted_time = str(datetime.fromtimestamp(current_time).strftime("%A, %B %d, %Y %I:%M:%S"))
            
            if current_time > timeout: # if block determines if there's high traffic or low traffic(diagnostic message)
                traffic_str = self.return_traffic_type(converted_time) 
                if traffic_str:
                    print(traffic_str)
                    self.alerts.append(traffic_str)

                self.two_minutes.clear()
                timeout = time.time() + 60*2 
              

            packets = sniff(filter='tcp', prn=self.sniff_start, timeout=10) #Blocks and sniffs HTTP traffic: calls self.sniff_start and updates requests / seconds
            self.global_time.add_seconds(10)
            self.two_minutes.add_seconds(10)


            print("Current Time: {}".format(datetime.now()))
            
            print("HTTP Info:")
            

            if self.requests_dict: # if requests > 0
                base_site, num_hits = self.find_website_most_hits() #returns the base website with the most hits its number of hits
                print("\nWebsite: " + base_site)
                print("Website had " + str(num_hits) + " hits\n")
                self.print_max_links(base_site) 

            else:
                print("\nThere is no current website with max hits\n")
            

            self.interesting_stats(packets)
            self.requests_dict.clear()
            
        
            


def signal_handler(sig, frame):
    """ Handles interruptions, Used later in program to capture SIGINT"""
    print("\nStopped Program Successfully.")
    sys.exit(1)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    
    new = HttpDetector()
    new.start_sniffing()