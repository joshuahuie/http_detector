# HTTP_Detector

## Description

This Python application harnesses the power of packet manipulation tools like Scapy to sniff HTTP requests from your local computer and print them out to your console.

This application prints both detected http requests and the detected number of packets to the console every ten seconds. Specifically, it lists the most requested website along with its top three most requested sections. Lastly, this application generates alerts whenever the traffic for the past two minutes exceeds or drops from the average total traffic. 


## Quick Start
Application must be run as a root user.
To get started with the app quickly, run make:

```
make 
```

## Test Cases

To run testcases on the alerting logic, run:

```
make test
```

## Manual Run

Application must be run as a root user
To run the application manually, first install all the dependencies located in requirements.txt:

```
pip install -r requirements.txt
```

Lastly, run the http_detector app:

```
python2 HttpDetector.py
```

## Exiting the Program

To quit the program, interrupt the program by pressing ctrl + c.
