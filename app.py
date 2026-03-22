import os
import json
import hashlib
import math
import struct
import pickle
import numpy as np
from flask import Flask, request, jsonify, send_from_directory, make_response
from collections import Counter
import threading

app = Flask(__name__, static_folder="static", template_folder="templates")

@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

@app.route('/api/<path:path>', methods=['OPTIONS'])
def options_handler(path):
    return make_response('', 204)

MODEL_PATH = "model/classifier.pkl"
LABEL_PATH = "model/labels.json"

MALWARE_FAMILIES = [
    "Ramnit", "Lollipop", "Kelihos_ver3", "Vundo", "Simda",
    "Tracur", "Kelihos_ver1", "Obfuscator.ACY", "Gatak", "Benign"
]

_model = None
_labels = None
_model_lock = threading.Lock()

def get_model():
    global _model, _labels
    with _model_lock:
        if _model is None:
            if os.path.exists(MODEL_PATH) and os.path.exists(LABEL_PATH):
                with open(MODEL_PATH, "rb") as f:
                    _model = pickle.load(f)
                with open(LABEL_PATH, "r") as f:
                    _labels = json.load(f)
    return _model, _labels

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

def extract_byte_histogram(data: bytes) -> list:
    histogram = [0] * 256
    for byte in data:
        histogram[byte] += 1
    total = len(data) if len(data) > 0 else 1
    return [c / total for c in histogram]

def extract_features(data: bytes) -> np.ndarray:
    features = []

    features.append(len(data))
    features.append(calculate_entropy(data))

    histogram = extract_byte_histogram(data)
    features.extend(histogram)

    chunk_size = max(1, len(data) // 8)
    for i in range(8):
        chunk = data[i*chunk_size:(i+1)*chunk_size]
        features.append(calculate_entropy(chunk) if chunk else 0.0)

    printable = sum(1 for b in data if 32 <= b <= 126)
    features.append(printable / len(data) if data else 0)

    null_bytes = data.count(0)
    features.append(null_bytes / len(data) if data else 0)

    high_bytes = sum(1 for b in data if b > 127)
    features.append(high_bytes / len(data) if data else 0)

    pe_header = 1 if data[:2] == b'MZ' else 0
    features.append(pe_header)

    elf_header = 1 if data[:4] == b'\x7fELF' else 0
    features.append(elf_header)

    suspicious_strings = [
        b'CreateRemoteThread', b'VirtualAlloc', b'WriteProcessMemory',
        b'ShellExecute', b'WinExec', b'URLDownloadToFile',
        b'RegSetValue', b'socket', b'connect', b'cmd.exe',
        b'powershell', b'base64', b'decrypt', b'encrypt'
    ]
    for s in suspicious_strings:
        features.append(1 if s in data else 0)

    url_indicators = [b'http://', b'https://', b'ftp://']
    url_count = sum(data.count(u) for u in url_indicators)
    features.append(min(url_count, 20) / 20)

    if len(data) >= 4:
        first_dword = struct.unpack('<I', data[:4])[0] if len(data) >= 4 else 0
        features.append(first_dword % 256 / 255)
    else:
        features.append(0)

    features.append(len(set(data)) / 256)

    bigram_sample = {}
    step = max(1, len(data) // 1000)
    for i in range(0, min(len(data)-1, 2000), step):
        bg = (data[i], data[i+1])
        bigram_sample[bg] = bigram_sample.get(bg, 0) + 1
    features.append(len(bigram_sample) / 65536)

    return np.array(features, dtype=np.float32)

def get_file_type(data: bytes) -> str:
    if data[:2] == b'MZ':
        return "PE Executable (Windows)"
    elif data[:4] == b'\x7fELF':
        return "ELF Executable (Linux)"
    elif data[:4] == b'%PDF':
        return "PDF Document"
    elif data[:2] == b'PK':
        return "ZIP Archive"
    elif data[:3] == b'#!/' or data[:2] == b'#!':
        return "Script"
    elif all(32 <= b <= 126 or b in (9, 10, 13) for b in data[:512]):
        return "Text/Script File"
    else:
        return "Unknown Binary"

@app.route("/")
def index():
    return send_from_directory("templates", "index.html")

@app.route("/api/classify", methods=["POST"])
def classify():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    data = file.read()
    if len(data) == 0:
        return jsonify({"error": "Empty file"}), 400

    features = extract_features(data)
    file_hash = hashlib.sha256(data).hexdigest()
    file_type = get_file_type(data)
    entropy = calculate_entropy(data)

    model, labels = get_model()

    if model is None:
        import random
        random.seed(int(file_hash[:8], 16))
        weights = [random.random() for _ in MALWARE_FAMILIES]
        total = sum(weights)
        probabilities = {fam: round(w/total * 100, 2) for fam, w in zip(MALWARE_FAMILIES, weights)}
        predicted = max(probabilities, key=probabilities.get)
        confidence = probabilities[predicted]
    else:
        features_2d = features.reshape(1, -1)
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(features_2d)[0]
            predicted_idx = np.argmax(proba)
            predicted = labels[predicted_idx]
            probabilities = {labels[i]: round(float(proba[i]) * 100, 2) for i in range(len(labels))}
            confidence = round(float(proba[predicted_idx]) * 100, 2)
        else:
            predicted_idx = model.predict(features_2d)[0]
            predicted = labels[predicted_idx]
            probabilities = {fam: 0.0 for fam in labels}
            probabilities[predicted] = 100.0
            confidence = 100.0

    histogram = extract_byte_histogram(data)
    chunk_entropies = []
    chunk_size = max(1, len(data) // 16)
    for i in range(16):
        chunk = data[i*chunk_size:(i+1)*chunk_size]
        chunk_entropies.append(round(calculate_entropy(chunk), 4) if chunk else 0.0)

    suspicious_found = []
    suspicious_strings = [
        ('CreateRemoteThread', b'CreateRemoteThread'),
        ('VirtualAlloc', b'VirtualAlloc'),
        ('WriteProcessMemory', b'WriteProcessMemory'),
        ('ShellExecute', b'ShellExecute'),
        ('WinExec', b'WinExec'),
        ('URLDownloadToFile', b'URLDownloadToFile'),
        ('RegSetValue', b'RegSetValue'),
        ('socket()', b'socket'),
        ('cmd.exe', b'cmd.exe'),
        ('PowerShell', b'powershell'),
    ]
    for name, pattern in suspicious_strings:
        if pattern in data:
            suspicious_found.append(name)

    is_malicious = predicted != "Benign"
    threat_level = "CLEAN"
    if is_malicious:
        if confidence > 80:
            threat_level = "CRITICAL"
        elif confidence > 60:
            threat_level = "HIGH"
        elif confidence > 40:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

    return jsonify({
        "filename": file.filename,
        "file_size": len(data),
        "file_type": file_type,
        "sha256": file_hash,
        "entropy": round(entropy, 4),
        "predicted_family": predicted,
        "confidence": confidence,
        "threat_level": threat_level,
        "is_malicious": is_malicious,
        "probabilities": dict(sorted(probabilities.items(), key=lambda x: -x[1])[:10]),
        "byte_histogram": [round(v, 6) for v in histogram],
        "chunk_entropies": chunk_entropies,
        "suspicious_strings": suspicious_found,
        "feature_count": len(features),
        "model_loaded": model is not None
    })

@app.route("/api/status", methods=["GET"])
def status():
    model, labels = get_model()
    return jsonify({
        "model_loaded": model is not None,
        "families": MALWARE_FAMILIES,
        "version": "1.0.0"
    })

if __name__ == "__main__":
    os.makedirs("model", exist_ok=True)
    app.run(debug=True, port=5000)