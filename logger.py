import csv
from datetime import datetime

def log(file, score, verdict):
    with open("logs/usb_log.csv", "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([datetime.now(), file, score, verdict])
