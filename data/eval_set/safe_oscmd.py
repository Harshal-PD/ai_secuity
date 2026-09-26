import os

def stop_process(pid):
    # integer cast removes every shell metacharacter
    os.system("kill -9 " + str(int(pid)))
