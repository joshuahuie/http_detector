from average_time import average_time

new = average_time()
other = average_time()
new.add_requests(300)
new.add_seconds(60)
other.add_requests(5)
other.add_seconds(1)

print(new == other)