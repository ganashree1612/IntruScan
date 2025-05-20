protocol_encoding = {"tcp": 0, "udp": 1, "icmp": 2}
service_encoding = {
    "http": 0,
    "ftp_data": 1,
    "private": 2,
    "other": 3,
}  # expand as needed
flag_encoding = {"SF": 0, "S0": 1, "REJ": 2, "RSTO": 3, "OTH": 4}  # expand as needed

attack_category_map = {
    "back": "DoS Attack",
    "land": "DoS Attack",
    "neptune": "DoS Attack",
    "pod": "DoS Attack",
    "smurf": "DoS Attack",
    "teardrop": "DoS Attack",
    "ipsweep": "Probe Attack",
    "nmap": "Probe Attack",
    "portsweep": "Probe Attack",
    "satan": "Probe Attack",
    "ftp_write": "R2L Attack",
    "guess_passwd": "R2L Attack",
    "imap": "R2L Attack",
    "multihop": "R2L Attack",
    "phf": "R2L Attack",
    "spy": "R2L Attack",
    "warezclient": "R2L Attack",
    "warezmaster": "R2L Attack",
    "buffer_overflow": "U2R Attack",
    "loadmodule": "U2R Attack",
    "perl": "U2R Attack",
    "rootkit": "U2R Attack",
    "normal": "Normal",
}


def encode_features(features):
    # features is a list where
    # index 1 = protocol_type (string)
    # index 2 = service (string)
    # index 3 = flag (string)
    # We encode these to int for model input
    features[1] = protocol_encoding.get(features[1].lower(), protocol_encoding["tcp"])
    features[2] = service_encoding.get(features[2].lower(), service_encoding["other"])
    features[3] = flag_encoding.get(features[3].upper(), flag_encoding["OTH"])
    return features


def classify_packet(raw_features):
    features = encode_features(raw_features)
    prediction = model.predict([np.array(features)])
    attack_name = str(prediction[0]).lower().strip()
    attack_type = attack_category_map.get(attack_name, "Unknown Attack")
    return attack_type
