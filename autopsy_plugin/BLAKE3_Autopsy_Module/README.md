# BLAKE3 Autopsy Module – Installation Guide

## What This Is
An Autopsy ingest module that hashes every evidence file using an optimized
BLAKE3 implementation with:
- Adaptive chunk & buffer handling
- Multithreaded parallel processing
- SIMD-aware execution (AVX-512 / AVX2 / SSE4.1 / SSE2)

Results appear in Autopsy's Blackboard as "BLAKE3 Hash (Optimized)" artifacts.

## Files in This Folder
```
BLAKE3_Autopsy_Module/
├── OptimizedBLAKE3Ingest.py     ← Autopsy Jython ingest module
├── optimized_blake3_hasher.exe  ← Optimized BLAKE3 engine (standalone)
└── README.md                    ← This file
```

## Installation Steps

### Step 1 – Open the Autopsy Python Plugins folder
1. Open Autopsy
2. Go to **Tools → Python Plugins**
3. A folder window will open — this is your `python_modules` directory
   (usually `C:\Users\<YourName>\AppData\Roaming\autopsy\python_modules\`)

### Step 2 – Copy the module folder
Copy the entire `BLAKE3_Autopsy_Module/` folder into the `python_modules/` directory:
```
python_modules/
└── BLAKE3_Autopsy_Module/
    ├── OptimizedBLAKE3Ingest.py
    ├── optimized_blake3_hasher.exe
    └── README.md
```

### Step 3 – Restart Autopsy
Close and reopen Autopsy so it picks up the new module.

### Step 4 – Enable the module in a case
1. Open or create a case
2. Click **Ingest** (or right-click a data source → Run Ingest Modules)
3. In the module list, tick **"Optimized BLAKE3 Hasher"**
4. Click **Finish**

### Step 5 – View results
After ingest completes:
- In the left panel, go to **Results → Extracted Content**
- Find **"BLAKE3 Hash (Optimized)"**
- Each evidence file will have these attributes:
  - **BLAKE3 Hash Digest** — the 256-bit hex hash
  - **SIMD Tier** — e.g., "AVX-512"
  - **Threads Used** — e.g., 12
  - **Execution Time (s)**
  - **Throughput (MB/s)**
  - **File Size (bytes)**

## Requirements
- Autopsy 4.x or later (Windows)
- No Python installation needed — the `.exe` is self-contained
