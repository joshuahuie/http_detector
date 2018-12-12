import unittest
from HttpDetector import HttpDetector as hd
import time
from datetime import datetime

class TestCases(unittest.TestCase):
    def test_alert_logic_no_difference(self):
        new_detector = hd()
        new_detector.avg_two_min_time.set_sec_req(40,50)
        new_detector.avg_global_time.set_sec_req(40,50)

        self.assertEqual(new_detector.return_traffic_type(time.time()),None)

    def test_alert_logic_less_than(self):
        new_detector = hd()
        new_detector.avg_two_min_time.set_sec_req(0,0)
        new_detector.avg_global_time.set_sec_req(50,50)


        current_time = time.time()
        converted_time = str(datetime.fromtimestamp(current_time).strftime("%A, %B %d, %Y %I:%M:%S"))
        built_string = "Low traffic generated an alert - hits = {value}, triggered at {time}".format(value=new_detector.avg_two_min_time.return_requests(),time=converted_time)
        
        self.assertLess(new_detector.avg_two_min_time,new_detector.avg_global_time)
        self.assertEqual(new_detector.return_traffic_type(converted_time),built_string)

    def test_alert_logic_greater_than(self):
        new_detector = hd()
        new_detector.avg_two_min_time.set_sec_req(30,90)
        new_detector.avg_global_time.set_sec_req(10,20)


        current_time = time.time()
        converted_time = str(datetime.fromtimestamp(current_time).strftime("%A, %B %d, %Y %I:%M:%S"))
        built_string = "High traffic generated an alert - hits = {value}, triggered at {time}".format(value=new_detector.avg_two_min_time.return_requests(),time=converted_time)
        
        self.assertGreater(new_detector.avg_two_min_time,new_detector.avg_global_time)
        self.assertEqual(new_detector.return_traffic_type(converted_time),built_string)


if __name__ == '__main__':
    unittest.main()