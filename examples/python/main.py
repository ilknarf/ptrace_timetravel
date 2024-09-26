import time
from datetime import datetime

'''
Try running `cargo run python3 examples/python/main.py`
'''
if __name__ == '__main__':
    # doesn't use clock_gettime under the hood
    print(time.ctime())
    # often runs into parsing error because invalid timestamp (e.g., huge year number)
    print(datetime.fromtimestamp(time.clock_gettime(time.CLOCK_REALTIME) / 1000))