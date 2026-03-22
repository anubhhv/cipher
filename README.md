# CIPHER — Malware Static Analysis Engine

Classify malware families from raw binary files using static analysis — no execution required.

---

## 🚀 Overview

CIPHER is an AI-powered malware analysis system that extracts 300+ structural and statistical features from raw binary files and classifies them into known malware families or benign files using a trained Random Forest model.

Everything runs locally. No file execution. No sandboxing. Just pure static intelligence.

---

## ✨ Features

* 🧠 **AI-Based Classification**: Random Forest model trained on malware patterns
* 🔍 **Static Analysis Only**: No execution required, fully safe analysis
* 📊 **314 Feature Extraction**: Entropy, byte distribution, API patterns, and more
* ⚡ **Instant Results**: Real-time classification with confidence scores
* 🎯 **Threat Scoring**: Categorized threat levels (Clean → Critical)
* 🧾 **SHA-256 Fingerprinting**: Unique file identification
* 🎨 **Interactive UI**: Cyberpunk dashboard with visual analytics

---

## 🏗️ Project Structure

```id="sdf82k"
cipher/
│
├── app.py
├── train.py
├── requirements.txt
│
├── model/
│   ├── classifier.pkl
│   ├── labels.json
│   └── meta.json
│
├── templates/
│   └── index.html
│
├── static/
│   ├── css/style.css
│   └── js/main.js
│
└── samples/
```

---

## ⚙️ Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/anubhhv/cipher.git
   cd cipher
   ```

2. Install dependencies:

   ```bash
   pip install flask numpy scikit-learn
   ```

3. Train the model:

   ```bash
   python train.py
   ```

4. Run the server:

   ```bash
   python app.py
   ```

5. Open in browser:

   ```
   http://localhost:5000
   ```

---

## 📈 Usage

* Upload any binary file through the UI
* System extracts features and classifies instantly
* View:

  * Predicted malware family
  * Confidence score
  * Threat level
  * Entropy and byte analysis

---

## 🧠 Malware Families

Supports classification into multiple malware families including:

* Ramnit
* Lollipop
* Kelihos (v1 & v3)
* Vundo
* Simda
* Tracur
* Obfuscator.ACY
* Gatak
* Benign

---

## ⚙️ How It Works

1. **Feature Extraction**
   Extracts 314 features including entropy, byte frequency, and API indicators

2. **Model Prediction**
   Random Forest model classifies file into malware family

3. **Threat Scoring**
   Assigns severity level based on confidence

4. **Visualization**
   Displays entropy maps, histograms, and probability scores

---

## 🤖 Model Details

* Algorithm: Random Forest
* Trees: 300
* Accuracy: ~99%+
* Features: 314

---

## 📊 API Endpoint

### `POST /api/classify`

Upload a file and receive classification:

```json
{
  "predicted_family": "Kelihos_ver3",
  "confidence": 91.4,
  "threat_level": "CRITICAL"
}
```

---

## 📦 Dataset

Training is based on patterns derived from the Microsoft Malware Classification dataset.

Supports:

* Synthetic data generation
* Real dataset integration (Kaggle BIG 2015)

---

## 🔐 Disclaimer

This project is for educational and research purposes only. Do not use it on files without proper authorization.

---

## 📄 License

MIT License

---

**No execution. No sandbox. Just pure static intelligence.** 
