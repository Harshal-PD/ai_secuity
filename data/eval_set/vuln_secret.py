DB_PASSWORD = "Pr0d-Admin-2024!"

def connect(driver):
    return driver.connect(user="admin", password=DB_PASSWORD)
