import sys,time,random
from pathlib import Path
import httpx
API="http://127.0.0.1:8000/api/iot/data"; devices=[("ESP001",11.0168,76.9558),("ESP002",11.018,76.96),("ESP003",11.01,76.948),("ESP004",11.025,76.97),("ESP005",11.0,76.94)]
try:
    while True:
        for did,la,lo in devices:
            event=random.random()<.08; moved=random.random()<.05; payload={"device_id":did,"latitude":la+(random.uniform(1.1,2.0) if moved else random.uniform(-.002,.002)),"longitude":lo+(random.uniform(1.1,2.0) if moved else random.uniform(-.002,.002)),"vibration":random.uniform(.7,1.3) if event else random.uniform(.03,.25),"online":random.random()>.03}
            try: httpx.post(API,json=payload,timeout=3)
            except Exception: pass
        time.sleep(4)
except KeyboardInterrupt: print("Simulator stopped")

