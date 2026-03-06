import subprocess

def check_logfile_dirty_bit():
    print("[*] Checking $LogFile consistency...")
    # 'fsutil dirty query' checks if the LogFile has pending/uncommitted transactions
    # which is a sign of live tampering.
    cmd = "fsutil dirty query C:"
    
    try:
        result = subprocess.check_output(cmd, shell=True).decode()
        print(f"LOG STATUS: {result.strip()}")
        print("[FORENSIC NOTE] If 'Dirty', transactions exist in $LogFile that aren't in the MFT yet.")
    except:
        print("Admin access required.")

if __name__ == "__main__":
    check_logfile_dirty_bit()