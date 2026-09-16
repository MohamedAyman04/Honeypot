import os
import shutil
import glob

def check_space():
    # 1. Calculate smoke test directory size
    smoke_dir = "results/20260629_235150"
    total_smoke_size = 0
    for root, dirs, files in os.walk(smoke_dir):
        for f in files:
            fp = os.path.join(root, f)
            total_smoke_size += os.path.getsize(fp)
            
    print(f"Smoke test directory size: {total_smoke_size / 1024:.2f} KB ({total_smoke_size / (1024*1024):.4f} MB)")
    
    # 2. Scale to 3 hours (5 min -> 180 min, factor of 36)
    est_campaign_size = total_smoke_size * 36
    print(f"Estimated 3-hour campaign size: {est_campaign_size / (1024*1024):.2f} MB")
    
    # 3. Check disk space of the external drive
    path = os.getcwd()
    total, used, free = shutil.disk_usage(path)
    print(f"Disk path: {path}")
    print(f"Total space: {total / (1024**3):.2f} GB")
    print(f"Used space: {used / (1024**3):.2f} GB")
    print(f"Free space: {free / (1024**3):.2f} GB")
    
    # Check if free space is enough (with 20% headroom means we want free space to be > est_size * 1.2, which is trivial here, but let's check percentage free)
    percent_free = (free / total) * 100
    print(f"Percent free: {percent_free:.2f}%")
    
    if free > est_campaign_size * 1.2:
        print("DISK SPACE CHECK: PASSED")
    else:
        print("DISK SPACE CHECK: FAILED")

if __name__ == "__main__":
    check_space()
