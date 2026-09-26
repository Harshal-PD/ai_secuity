import os

def stop_process(user_pid):
    os.system("kill -9 " + user_pid)
