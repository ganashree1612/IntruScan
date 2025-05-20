# 🔒 Real-Time Intrusion Detection System (IDS) with Firewall IP Blocking

This project implements a real-time Intrusion Detection System using **Scapy** for packet sniffing, a **Machine Learning model** for classification, and system-level firewall commands to block malicious IPs. It's designed to detect network attacks such as DoS, Probe, R2L, and U2R using features inspired by the **NSL-KDD** dataset.

---

## 📁 Project Structure

IntruScan/
├── detection/
│ └── classifier.py # ML model to classify packets as normal or attack
├── firewall/
│ └── block_ip.py # Blocks IP using system firewall (Windows/Linux)
├── monitor/
│ └── sniffer.py # Captures and processes live packets
├── logs/
│ └── attack_log.txt # Logs intrusion alerts and blocked IPs
├── model/
│ └── rf_model.pkl # Trained Random Forest model (or any ML model)
├── README.md
1. Clone the Repo
git clone https://github.com/yourusername/intrusion-detection-system.git
run python main.py
cd dashboard
streamlit run main.py

Make sure you have Python 3.7+ and install the required packages:

pip install -r requirements.txt

Add Your Model
Place your trained ML model (e.g., rf_model.pkl) inside the model/ folder.

Update detection/classifier.py to load and use it accordingly.


Test Mode
You can simulate detection without modifying your firewall by setting:

TEST_MODE = True  # in firewall/block_ip.py
To enable real blocking:
TEST_MODE = False
