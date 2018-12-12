class AverageTime:
    """Class is compare and calculate averages from an inputted number of requests and seconds"""
    def __init__(self):
        """Initialize the class with a number
        of requests, seconds, and averages set to 0
        """
        self.requests = 0
        self.seconds = 0

        self.average = 0

    def clear(self):
        """Clears all the class variables"""
        self.requests = 0
        self.seconds = 0
        self.average = 0

    def set_sec_req(self,secs,reqs):
        """Assigns seconds and requests then
        computes the average"""
        self.seconds = secs
        self.requests = reqs 
        self.compute_average()
        
    def return_requests(self):
        """Returns the number of requests"""
        return self.requests
    
    def add_requests(self,amount):
        """Adds to the current request amount"""
        self.requests += amount
        self.compute_average()

    def add_seconds(self,amount):
        """Adds to the seconds class variable"""
        self.seconds += amount
        self.compute_average()
    
    def compute_average(self):
        """Computes the average requests / seconds """
        if self.seconds != 0:
            self.average = float(self.requests) / self.seconds

    def return_average(self):
        """Returns the average"""
        return self.average

    def __eq__(self,other):
        """Returns whether two AverageTime objects have the save average"""
        if other is None:
            return False

        return self.average == other.average

    def __lt__(self,other):
        """Returns whether one AverageTime object is less than the other's average"""
        return self.average < other.average

    def __str__(self):
        """This method defines the String representation when printing the object"""
        return "Requests:{}, Seconds:{}, Average:{}".format(self.requests,self.seconds,self.average)
    