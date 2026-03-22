import os
import json
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import warnings
warnings.filterwarnings('ignore')

MALWARE_FAMILIES = [
    "Ramnit", "Lollipop", "Kelihos_ver3", "Vundo", "Simda",
    "Tracur", "Kelihos_ver1", "Obfuscator.ACY", "Gatak", "Benign"
]

FAMILY_PROFILES = {
    "Ramnit": {
        "entropy": (6.4, 6.9), "entropy_std": 0.08,
        "chunk_variance": (0.4, 0.8),
        "pe": 0.97, "elf": 0.0,
        "size": (180000, 450000),
        "printable": (0.38, 0.48), "null": (0.04, 0.10),
        "apis": {"CreateRemoteThread":0.85,"VirtualAlloc":0.90,"WriteProcessMemory":0.80,
                 "ShellExecute":0.50,"WinExec":0.40,"URLDownloadToFile":0.70,
                 "RegSetValue":0.75,"socket":0.85,"connect":0.88,"cmd.exe":0.30,
                 "powershell":0.10,"base64":0.20,"decrypt":0.30,"encrypt":0.25},
        "urls": (1, 4), "unique_bytes": (0.92, 0.99), "bigram_div": (0.70, 0.85),
        "sections": (4, 7), "imports": (60, 120), "strings": (150, 400),
        "avg_str_len": (6.0, 9.0), "overlay": (0.0, 0.05),
    },
    "Lollipop": {
        "entropy": (5.6, 6.3), "entropy_std": 0.12,
        "chunk_variance": (0.6, 1.2),
        "pe": 0.88, "elf": 0.0,
        "size": (40000, 180000),
        "printable": (0.44, 0.60), "null": (0.02, 0.07),
        "apis": {"CreateRemoteThread":0.20,"VirtualAlloc":0.55,"WriteProcessMemory":0.30,
                 "ShellExecute":0.80,"WinExec":0.60,"URLDownloadToFile":0.85,
                 "RegSetValue":0.90,"socket":0.40,"connect":0.45,"cmd.exe":0.65,
                 "powershell":0.70,"base64":0.55,"decrypt":0.20,"encrypt":0.15},
        "urls": (3, 8), "unique_bytes": (0.75, 0.90), "bigram_div": (0.55, 0.70),
        "sections": (3, 5), "imports": (30, 70), "strings": (300, 700),
        "avg_str_len": (8.0, 14.0), "overlay": (0.0, 0.02),
    },
    "Kelihos_ver3": {
        "entropy": (7.3, 7.85), "entropy_std": 0.04,
        "chunk_variance": (0.02, 0.12),
        "pe": 0.99, "elf": 0.0,
        "size": (70000, 160000),
        "printable": (0.10, 0.22), "null": (0.01, 0.04),
        "apis": {"CreateRemoteThread":0.70,"VirtualAlloc":0.95,"WriteProcessMemory":0.90,
                 "ShellExecute":0.30,"WinExec":0.25,"URLDownloadToFile":0.60,
                 "RegSetValue":0.50,"socket":0.98,"connect":0.98,"cmd.exe":0.20,
                 "powershell":0.05,"base64":0.80,"decrypt":0.90,"encrypt":0.90},
        "urls": (0, 2), "unique_bytes": (0.97, 1.00), "bigram_div": (0.90, 0.99),
        "sections": (2, 4), "imports": (10, 30), "strings": (20, 80),
        "avg_str_len": (4.0, 7.0), "overlay": (0.3, 0.7),
    },
    "Vundo": {
        "entropy": (6.0, 6.6), "entropy_std": 0.15,
        "chunk_variance": (0.8, 1.8),
        "pe": 0.92, "elf": 0.0,
        "size": (25000, 100000),
        "printable": (0.30, 0.48), "null": (0.05, 0.14),
        "apis": {"CreateRemoteThread":0.60,"VirtualAlloc":0.80,"WriteProcessMemory":0.70,
                 "ShellExecute":0.65,"WinExec":0.55,"URLDownloadToFile":0.75,
                 "RegSetValue":0.85,"socket":0.30,"connect":0.35,"cmd.exe":0.40,
                 "powershell":0.25,"base64":0.60,"decrypt":0.65,"encrypt":0.60},
        "urls": (1, 5), "unique_bytes": (0.82, 0.94), "bigram_div": (0.62, 0.78),
        "sections": (3, 6), "imports": (40, 90), "strings": (100, 280),
        "avg_str_len": (5.5, 8.5), "overlay": (0.0, 0.03),
    },
    "Simda": {
        "entropy": (7.6, 7.95), "entropy_std": 0.02,
        "chunk_variance": (0.01, 0.05),
        "pe": 0.99, "elf": 0.0,
        "size": (30000, 90000),
        "printable": (0.06, 0.15), "null": (0.01, 0.03),
        "apis": {"CreateRemoteThread":0.50,"VirtualAlloc":0.99,"WriteProcessMemory":0.95,
                 "ShellExecute":0.20,"WinExec":0.15,"URLDownloadToFile":0.30,
                 "RegSetValue":0.40,"socket":0.60,"connect":0.65,"cmd.exe":0.10,
                 "powershell":0.05,"base64":0.95,"decrypt":0.98,"encrypt":0.98},
        "urls": (0, 1), "unique_bytes": (0.99, 1.00), "bigram_div": (0.95, 1.00),
        "sections": (1, 3), "imports": (5, 20), "strings": (10, 40),
        "avg_str_len": (3.0, 5.5), "overlay": (0.5, 0.9),
    },
    "Tracur": {
        "entropy": (4.8, 5.8), "entropy_std": 0.20,
        "chunk_variance": (1.5, 3.5),
        "pe": 0.72, "elf": 0.0,
        "size": (15000, 80000),
        "printable": (0.55, 0.78), "null": (0.01, 0.05),
        "apis": {"CreateRemoteThread":0.10,"VirtualAlloc":0.35,"WriteProcessMemory":0.20,
                 "ShellExecute":0.90,"WinExec":0.85,"URLDownloadToFile":0.95,
                 "RegSetValue":0.60,"socket":0.25,"connect":0.30,"cmd.exe":0.80,
                 "powershell":0.88,"base64":0.70,"decrypt":0.10,"encrypt":0.08},
        "urls": (5, 15), "unique_bytes": (0.60, 0.80), "bigram_div": (0.40, 0.60),
        "sections": (2, 4), "imports": (15, 45), "strings": (400, 900),
        "avg_str_len": (12.0, 22.0), "overlay": (0.0, 0.01),
    },
    "Kelihos_ver1": {
        "entropy": (7.0, 7.5), "entropy_std": 0.07,
        "chunk_variance": (0.08, 0.28),
        "pe": 0.98, "elf": 0.0,
        "size": (55000, 140000),
        "printable": (0.15, 0.28), "null": (0.02, 0.06),
        "apis": {"CreateRemoteThread":0.65,"VirtualAlloc":0.88,"WriteProcessMemory":0.82,
                 "ShellExecute":0.28,"WinExec":0.22,"URLDownloadToFile":0.55,
                 "RegSetValue":0.45,"socket":0.92,"connect":0.93,"cmd.exe":0.18,
                 "powershell":0.05,"base64":0.72,"decrypt":0.78,"encrypt":0.76},
        "urls": (0, 2), "unique_bytes": (0.94, 0.99), "bigram_div": (0.82, 0.94),
        "sections": (2, 4), "imports": (8, 25), "strings": (15, 65),
        "avg_str_len": (4.0, 6.5), "overlay": (0.1, 0.5),
    },
    "Obfuscator.ACY": {
        "entropy": (7.8, 7.99), "entropy_std": 0.015,
        "chunk_variance": (0.002, 0.03),
        "pe": 0.78, "elf": 0.0,
        "size": (8000, 60000),
        "printable": (0.02, 0.10), "null": (0.001, 0.02),
        "apis": {"CreateRemoteThread":0.30,"VirtualAlloc":0.95,"WriteProcessMemory":0.85,
                 "ShellExecute":0.10,"WinExec":0.08,"URLDownloadToFile":0.20,
                 "RegSetValue":0.25,"socket":0.40,"connect":0.42,"cmd.exe":0.05,
                 "powershell":0.03,"base64":0.98,"decrypt":0.99,"encrypt":0.99},
        "urls": (0, 1), "unique_bytes": (0.99, 1.00), "bigram_div": (0.97, 1.00),
        "sections": (1, 2), "imports": (3, 12), "strings": (5, 25),
        "avg_str_len": (3.0, 4.5), "overlay": (0.7, 0.95),
    },
    "Gatak": {
        "entropy": (6.1, 6.7), "entropy_std": 0.10,
        "chunk_variance": (0.5, 1.0),
        "pe": 0.90, "elf": 0.0,
        "size": (60000, 220000),
        "printable": (0.35, 0.52), "null": (0.03, 0.09),
        "apis": {"CreateRemoteThread":0.45,"VirtualAlloc":0.70,"WriteProcessMemory":0.60,
                 "ShellExecute":0.55,"WinExec":0.45,"URLDownloadToFile":0.65,
                 "RegSetValue":0.70,"socket":0.50,"connect":0.55,"cmd.exe":0.35,
                 "powershell":0.20,"base64":0.40,"decrypt":0.50,"encrypt":0.48},
        "urls": (1, 4), "unique_bytes": (0.84, 0.95), "bigram_div": (0.65, 0.80),
        "sections": (4, 8), "imports": (50, 110), "strings": (200, 500),
        "avg_str_len": (6.5, 10.0), "overlay": (0.0, 0.04),
    },
    "Benign": {
        "entropy": (3.2, 5.8), "entropy_std": 0.35,
        "chunk_variance": (1.5, 5.0),
        "pe": 0.60, "elf": 0.06,
        "size": (2000, 2000000),
        "printable": (0.58, 0.92), "null": (0.001, 0.025),
        "apis": {"CreateRemoteThread":0.01,"VirtualAlloc":0.08,"WriteProcessMemory":0.02,
                 "ShellExecute":0.12,"WinExec":0.04,"URLDownloadToFile":0.02,
                 "RegSetValue":0.10,"socket":0.06,"connect":0.08,"cmd.exe":0.03,
                 "powershell":0.05,"base64":0.07,"decrypt":0.02,"encrypt":0.02},
        "urls": (0, 3), "unique_bytes": (0.45, 0.82), "bigram_div": (0.28, 0.62),
        "sections": (3, 8), "imports": (20, 200), "strings": (100, 1000),
        "avg_str_len": (7.0, 18.0), "overlay": (0.0, 0.01),
    }
}

API_NAMES = [
    "CreateRemoteThread","VirtualAlloc","WriteProcessMemory","ShellExecute",
    "WinExec","URLDownloadToFile","RegSetValue","socket",
    "connect","cmd.exe","powershell","base64","decrypt","encrypt"
]

def make_sample(family: str, rng: np.random.Generator) -> list:
    p = FAMILY_PROFILES[family]
    f = []

    size = rng.integers(p["size"][0], p["size"][1])
    f.append(np.log1p(size) / np.log1p(2_000_000))

    entropy = float(np.clip(rng.normal(np.mean(p["entropy"]), p["entropy_std"]),
                            p["entropy"][0] - 0.3, p["entropy"][1] + 0.3))
    f.append(entropy / 8.0)
    f.append(entropy)

    var = rng.uniform(*p["chunk_variance"])
    chunks = [float(np.clip(entropy + rng.normal(0, np.sqrt(var / 16)), 0, 8)) for _ in range(16)]
    f.extend([c / 8.0 for c in chunks])
    f.append(float(np.var(chunks)) / 8.0)
    f.append(float(np.mean(chunks)) / 8.0)
    f.append((max(chunks) - min(chunks)) / 8.0)

    conc = max(0.05, 3.5 - entropy)
    hist = rng.dirichlet(np.ones(256) * conc)
    f.extend(hist.tolist())

    printable = float(np.clip(rng.normal(np.mean(p["printable"]), 0.04), 0.0, 1.0))
    null_r    = float(np.clip(rng.normal(np.mean(p["null"]), 0.01), 0.0, 1.0))
    high_b    = float(np.clip(1.0 - printable - null_r + rng.normal(0, 0.02), 0.0, 1.0))
    f += [printable, null_r, high_b]

    pe  = 1 if rng.random() < p["pe"]  else 0
    elf = 1 if (rng.random() < p["elf"] and pe == 0) else 0
    f += [pe, elf]

    api_hits = []
    for api in API_NAMES:
        hit = 1 if rng.random() < p["apis"].get(api, 0.04) else 0
        f.append(hit)
        api_hits.append(hit)
    f.append(sum(api_hits) / len(API_NAMES))

    urls = rng.integers(p["urls"][0], max(p["urls"][1]+1, p["urls"][0]+1))
    f.append(min(urls, 20) / 20.0)

    ub = float(np.clip(rng.normal(np.mean(p["unique_bytes"]), 0.015), 0, 1))
    bd = float(np.clip(rng.normal(np.mean(p["bigram_div"]),   0.020), 0, 1))
    f += [ub, bd]

    sec = rng.integers(p["sections"][0], p["sections"][1]+1)
    imp = rng.integers(p["imports"][0],  p["imports"][1]+1)
    st  = rng.integers(p["strings"][0],  p["strings"][1]+1)
    asl = float(np.clip(rng.normal(np.mean(p["avg_str_len"]), 1.5), 2, 35))
    ov  = float(np.clip(rng.normal(np.mean(p["overlay"]), 0.04), 0, 1))
    f += [sec/10.0, np.log1p(imp)/np.log1p(250), np.log1p(st)/np.log1p(1200), asl/35.0, ov]

    f += [
        entropy * ov,
        entropy * (1 - printable),
        float(pe) * sum(api_hits) / len(API_NAMES),
        ub * entropy / 8.0,
        float(sec) * ov,
        printable * (1 - ov),
        bd * ub,
        float(urls) * entropy / 8.0,
    ]

    return f

def generate_dataset(n: int = 1500):
    print(f"[*] Generating dataset ({n} samples × {len(MALWARE_FAMILIES)} families)...")
    rng = np.random.default_rng(42)
    X_list, y_list = [], []
    for i, fam in enumerate(MALWARE_FAMILIES):
        rows = [make_sample(fam, rng) for _ in range(n)]
        X_list.append(np.array(rows, dtype=np.float32))
        y_list.extend([i] * n)
        print(f"  [{i+1:02}/{len(MALWARE_FAMILIES)}] {fam:20s}  {n} samples")
    X = np.vstack(X_list)
    y = np.array(y_list)
    idx = rng.permutation(len(X))
    return X[idx], y[idx]

def train_model():
    print("\n" + "="*60)
    print("  CIPHER — MALWARE CLASSIFIER TRAINING")
    print("="*60 + "\n")

    X, y = generate_dataset()
    print(f"\n[*] Shape: {X.shape}  |  Classes: {len(MALWARE_FAMILIES)}\n")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )

    print("[*] Training Random Forest (300 trees)...")
    rf = RandomForestClassifier(
        n_estimators=300, max_depth=None,
        min_samples_split=2, min_samples_leaf=1,
        max_features='sqrt', n_jobs=-1,
        random_state=42, class_weight='balanced',
        bootstrap=True, oob_score=True,
    )
    rf.fit(X_train, y_train)

    y_pred = rf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n[+] Accuracy  : {acc:.4f} ({acc*100:.2f}%)")
    print(f"[+] OOB Score : {rf.oob_score_:.4f}")
    print("\n[*] Per-class Report:")
    print(classification_report(y_test, y_pred, target_names=MALWARE_FAMILIES))

    os.makedirs("model", exist_ok=True)
    with open("model/classifier.pkl", "wb") as fh:
        pickle.dump(rf, fh)
    with open("model/labels.json", "w") as fh:
        json.dump(MALWARE_FAMILIES, fh)
    meta = {
        "accuracy": float(acc),
        "oob_score": float(rf.oob_score_),
        "families": MALWARE_FAMILIES,
        "feature_count": int(X.shape[1]),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "model_type": "RandomForest300"
    }
    with open("model/meta.json", "w") as fh:
        json.dump(meta, fh, indent=2)

    print("[+] Saved → model/classifier.pkl")
    print("[+] Saved → model/labels.json")
    print("[+] Saved → model/meta.json")
    print("\n" + "="*60)
    print("  COMPLETE — ~20 seconds total")
    print("="*60 + "\n")

if __name__ == "__main__":
    train_model()