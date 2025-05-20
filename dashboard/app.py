import streamlit as st
import time
st.title("🛡️ Intrusion Detection Firewall Dashboard")
def load_logs():
    # Your function to load logs from file or source
    with open("C:/Users/ganas/Desktop/IntruScan/logs/attack_log.txt", "r") as f:
        return f.readlines()

while True:
    st.subheader("⚠️ Attack Logs")
    logs = load_logs()
    for log in logs[-20:]:
        # Print each log line in red using markdown and HTML span with style
        st.markdown(f"<span style='color:red'>{log.strip()}</span>", unsafe_allow_html=True)
    time.sleep(10)
    # st.experimental_rerun()
