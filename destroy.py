import vagrant
import os
import time

path ='C:\\Users\\hax0r\\projects\\loop\\'
with open('hostnames.txt','r') as f:
    hostnames = f.readlines()
    for hostname in hostnames:
        os.chdir(path)
        os.system('vagrant destroy --force {}'.format(hostname))
        time.sleep(2)