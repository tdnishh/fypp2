import os
import psutil

def monitor(file_path=None):
    """
    Simulates behavioral analysis for the specific target file.
    Checks if the asset acts like or interacts with shell command interpreters.
    """
    score = 0
    
    # If no file is passed, return baseline safety score
    if not file_path:
        return score

    filename = os.path.basename(file_path).lower()

    # 1️⃣ Behavioral Simulation: Check if the file targets scripting shells
    # In a real security suite, this monitors if a process spawns a hidden shell window.
    if "powershell" in filename or "cmd" in filename:
        score += 3

    # 2️⃣ Behavioral Simulation: Detect if a user is trying to execute code via presentation files
    # Checks if a presentation script template tries to simulate hidden execution paths.
    elif filename.endswith(".bat") or filename.endswith(".ps1"):
        score += 2

    return score