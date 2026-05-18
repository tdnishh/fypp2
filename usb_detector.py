import win32file
import win32con

def detect_usb():
    drives = win32file.GetLogicalDrives()
    for i in range(26):
        if drives & (1 << i):
            drive = chr(65+i) + ":\\"
            if win32file.GetDriveType(drive) == win32con.DRIVE_REMOVABLE:
                return drive
    return None
