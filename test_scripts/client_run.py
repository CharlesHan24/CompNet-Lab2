import os
import time


for i in range(10):
    os.system("cd ../bin/; ./echo_client result1.txt 10.100.1.2 80 veth1-2 abcdefghigklmn")
    time.sleep(40)