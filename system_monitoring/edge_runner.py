
import json
import math
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from host_feature_collector import collect
from host_inference import predict_host
from network_pipeline import run_network_pipeline


def clean(value):
    if isinstance(value, dict):
        return {key: clean(val) for key, val in value.items()}

    if isinstance(value, list):
        return [clean(item) for item in value]

    if isinstance(value, float) and not math.isfinite(value):
        return None

    return value


def run_host_pipeline():
    print("\n[HOST] Monitoring started.")

    host_features = collect()
    host_result = predict_host(host_features)

    host_status = str(
        host_result["prediction"]
    ).strip().upper()

    print("\n[HOST] Prediction:", host_status)

    return host_result, host_status


def run_network_task():
    print("\n[NETWORK] Monitoring started.")

    capture_dir, network_features = run_network_pipeline()

    network_records = network_features.to_dict(
        orient="records"
    )

    network_predictions = [
        str(record.get("Network_prediction", "")).strip().upper()
        for record in network_records
    ]

    attack_count = network_predictions.count("ATTACK")
    normal_count = network_predictions.count("NORMAL")

    if not network_records:
        network_status = "UNKNOWN"
    elif attack_count > 0:
        network_status = "ATTACK"
    elif normal_count == len(network_records):
        network_status = "NORMAL"
    else:
        network_status = "UNKNOWN"

    print("\n[NETWORK] Prediction:", network_status)

    return (
        capture_dir,
        network_features,
        network_records,
        network_status,
        attack_count,
        normal_count
    )


def run_edge():

    print("\n========== EDGE PIPELINE STARTED ==========")
    print("Starting host and network monitoring simultaneously.")
    print("Expected monitoring duration: approximately 300 seconds.")

    # Start both independent pipelines concurrently.
    with ThreadPoolExecutor(max_workers=2) as executor:

        host_future = executor.submit(run_host_pipeline)
        network_future = executor.submit(run_network_task)

        # Wait for both pipelines to finish.
        host_result, host_status = host_future.result()

        (
            capture_dir,
            network_features,
            network_records,
            network_status,
            attack_count,
            normal_count
        ) = network_future.result()

    print("\nBoth monitoring pipelines completed.")

    # Final Edge decision.
    if host_status == "ATTACK" or network_status == "ATTACK":

        final_decision = "FORWARD_TO_FOG"

        if host_status == "ATTACK" and network_status == "ATTACK":
            reason = "Attack detected by both host and network models."
        elif host_status == "ATTACK":
            reason = "Attack detected by host model."
        else:
            reason = "Attack detected by network model."

    elif host_status == "NORMAL" and network_status == "NORMAL":

        final_decision = "CONTINUE_MONITORING"
        reason = "Both host and network models classified activity as normal."

    else:

        final_decision = "INCOMPLETE_DATA"
        reason = "Unable to make a complete decision from available predictions."

    # Display combined Edge result.
    print("\n========== EDGE LAYER OUTPUT ==========")

    print("HOST DETECTION      :", host_status)
    print("NETWORK DETECTION   :", network_status)
    print("TOTAL CONNECTIONS   :", len(network_records))
    print("ATTACK CONNECTIONS  :", attack_count)
    print("NORMAL CONNECTIONS  :", normal_count)

    print("\nFINAL EDGE DECISION :", final_decision)
    print("REASON              :", reason)

    print("=======================================")

    # Prepare Fog payload.
    payload = {
        "timestamp": datetime.now().astimezone().isoformat(),
        "edge_node": "raspberry_pi",
        "host": host_result,
        "network": {
            "capture_directory": str(capture_dir),
            "connection_count": len(network_records),
            "attack_count": attack_count,
            "normal_count": normal_count,
            "status": network_status,
            "predictions": network_records
        },
        "edge_decision": {
            "host_status": host_status,
            "network_status": network_status,
            "decision": final_decision,
            "reason": reason
        }
    }

    # Save combined output.
    output = Path("edge_output.json")

    with open(output, "w") as file:
        json.dump(clean(payload), file, indent=4, allow_nan=False)

    print("\nEdge output saved to:", output.resolve())
    print("\n========== EDGE PIPELINE COMPLETED ==========")


if __name__ == "__main__":
    run_edge()
