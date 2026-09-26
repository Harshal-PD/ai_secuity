import os

def connect(driver):
    return driver.connect(user="admin", password=os.environ["DB_PASSWORD"])
