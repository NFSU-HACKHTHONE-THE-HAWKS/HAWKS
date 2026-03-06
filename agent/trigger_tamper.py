import os
import time

# Path ekdum sync mein: C drive ke DAFDN_Demo folder wali file
file_path = r"C:\\DAFDN_Demo\\rehant.txt" # 'r' prefix zaroori hai error hatane ke liye

print(f"[*] Starting Timestomp Attack on: {file_path}")

# Pehle check karo ki file exist karti hai
if not os.path.exists("C:\\DAFDN_Demo"):
    os.makedirs("C:\\DAFDN_Demo")
    with open(file_path, "w") as f:
        f.write("Forensic Evidence Data")
if os.path.exists(file_path):
    # Timestomping: SI date ko 2 saal piche bhejo
    past_time = time.time() - (2 * 365 * 24 * 3600) 
    os.utime(file_path, (past_time, past_time))
    
    print("[+] Timestomping complete! $SI has been forged to 2 years ago.")
    print("[>] USN Journal still shows current time. Check Mac Dashboard!")
else:
    print(f"[!] Error: {file_path} nahi mili!")