import os

def scan_files(usb_path):
    files = []
    for root, dirs, filenames in os.walk(usb_path):
        for f in filenames:
            files.append(os.path.join(root, f))
    return files
