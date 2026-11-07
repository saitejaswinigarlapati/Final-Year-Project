import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import pandas as pd
from network_inference import predict_network

BASE_DIR = Path(__file__).resolve().parent
INTERFACE = "wlan0"
CAPTURE_SECONDS = 300

EXTRACTOR = (
    BASE_DIR / "network_logs/full_capture/run_02"
    / "extract_zeek_features_v2.py"
)

OUTPUT_DIR = BASE_DIR / "network_logs" / "live_captures"


def run_network_pipeline():

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    capture_dir = OUTPUT_DIR / timestamp
    capture_dir.mkdir(parents=True, exist_ok=True)

    pcap = capture_dir / "packets.pcap"
    packet_csv = capture_dir / "packet_details.csv"

    print("Starting network capture...")
    print("Interface:", INTERFACE)
    print("Duration:", CAPTURE_SECONDS, "seconds")

    subprocess.run(["sudo", "-n", "true"], check=True)

    zeek_log = open(capture_dir / "zeek_output.log", "w")

    zeek = subprocess.Popen(
        ["sudo", "-n", "/opt/zeek/bin/zeek", "-i", INTERFACE],
        cwd=capture_dir,
        stdout=zeek_log,
        stderr=subprocess.STDOUT,
        start_new_session=True
    )

    try:
        time.sleep(3)

        if zeek.poll() is not None:
            raise RuntimeError("Zeek failed to start. Check zeek_output.log")

        with open(pcap, "wb") as pcap_file:
            subprocess.run(
                [
                    "sudo", "-n", "tshark",
                    "-i", INTERFACE,
                    "-a", f"duration:{CAPTURE_SECONDS}",
                    "-w", "-"
                ],
                stdout=pcap_file,
                check=True
            )

    finally:
        if zeek.poll() is None:
            os.killpg(zeek.pid, signal.SIGINT)

            try:
                zeek.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(zeek.pid, signal.SIGTERM)
                zeek.wait()

        zeek_log.close()

    print("Capture completed.")

    fields = [
        "frame.time_epoch", "ip.src", "ip.proto",
        "tcp.srcport", "udp.srcport",
        "ip.dst", "tcp.dstport", "udp.dstport",
        "tcp.flags.syn", "tcp.flags.ack",
        "tcp.flags.reset", "tcp.flags.fin",
        "tcp.flags.push", "tcp.flags.urg",
        "tcp.len", "tcp.checksum.status"
    ]

    command = [
        "sudo", "-n", "tshark",
        "-r", str(pcap),
        "-Y", "tcp || udp",
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",
        "-E", "occurrence=f"
    ]

    for field in fields:
        command.extend(["-e", field])

    with open(packet_csv, "w") as output:
        subprocess.run(command, stdout=output, check=True)

    if not (capture_dir / "conn.log").exists():
        raise RuntimeError("Zeek conn.log was not generated.")

    print("Extracting network features...")

    subprocess.run(
        [sys.executable, str(EXTRACTOR)],
        cwd=capture_dir,
        check=True
    )

    features = pd.read_csv(capture_dir / "network_features_v2.csv")

    if features.empty:
        print("No network connections found.")
        return capture_dir, features

    print("Passing", len(features), "connections to network model...")

    results = predict_network(features)

    features["Network_prediction"] = [
        result["prediction"] for result in results
    ]

    features["Attack_probability"] = [
        result["probabilities"]["Attack"] for result in results
    ]

    features["Normal_probability"] = [
        result["probabilities"]["Normal"] for result in results
    ]

    features.to_csv(
        capture_dir / "network_predictions.csv",
        index=False
    )

    features.to_json(
        capture_dir / "network_predictions.json",
        orient="records",
        indent=2
    )

    print("\nNETWORK MODEL RESULTS")
    print(features["Network_prediction"].value_counts())
    print("\nSaved results to:", capture_dir)
    return capture_dir, features


if __name__ == "__main__":
    run_network_pipeline()
