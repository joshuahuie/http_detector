class average_time:
    def __init__(self):
        self.requests = 0
        self.seconds = 0

        self.average = 0

    def clear(self):
        self.requests = 0
        self.seconds = 0
        self.average = 0

    def set_sec_req(self,secs,reqs):
        self.seconds = secs
        self.requests = reqs 
        self.compute_average()
        
    def return_requests(self):
        return self.requests
    
    def add_requests(self,amount):
        self.requests += amount
        self.compute_average()

    def add_seconds(self,amount):
        self.seconds += amount
        self.compute_average()
    
    def compute_average(self):
        if self.seconds != 0:
            self.average = float(self.requests) / self.seconds

    def return_average(self):  
        return self.average

    def __eq__(self,other):
        if other is None:
            return False

        return self.average == other.average

    def __lt__(self,other):
        return self.average < other.average

    def __str__(self):
        return "Requests:{}, Seconds:{}, Average:{}".format(self.requests,self.seconds,self.average)
    