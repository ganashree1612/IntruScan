# 🔒 Real-Time Intrusion Detection System (IDS) with Firewall IP Blocking

This project implements a real-time Intrusion Detection System using **Scapy** for packet sniffing, a **Machine Learning model** for classification, and system-level firewall commands to block malicious IPs. It's designed to detect network attacks such as DoS, Probe, R2L, and U2R using features inspired by the **NSL-KDD** dataset.

---![WhatsApp Image 2025-05-20 at 20 36 08_0357916d](https://github.com/user-attachments/assets/c4e2327c-b12a-4910-bce7-ef75c7e15fb6)


## 📁 Project Structure


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
