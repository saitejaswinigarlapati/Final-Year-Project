import csv
from collections import defaultdict

ZEEK_INPUT = "conn.log"
PACKET_INPUT = "packet_details.csv"
OUTPUT = "network_features_v2.csv"

metadata = ["ts", "uid", "id.orig_h", "id.resp_h"]

numeric_features = [
    "Scr_port", "Des_port", "Duration", "Scr_bytes", "Des_bytes",
    "Conn_state", "missed_bytes",
    "is_syn_only", "Is_SYN_ACK", "is_pure_ack", "is_with_payload",
    "FIN or RST", "Bad_checksum", "is_SYN_with_RST",
    "Scr_pkts", "Scr_ip_bytes", "Des_pkts", "Des_ip_bytes",
    "total_bytes", "total_packet", "paket_rate", "byte_rate",
    "Scr_packts_ratio", "Des_pkts_ratio",
    "Scr_bytes_ratio", "Des_bytes_ratio"
]

categorical_features = ["Protocol", "Service"]
model_features = numeric_features + categorical_features


def number(value):
    if value in ("", "-", "(empty)", None):
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def truth(value):
    return str(value).lower() == "true"


def calculate_ratio(value, total):
    if value is None or total is None or total == 0:
        return ""
    return value / total


def endpoint_key(protocol, ip1, port1, ip2, port2):
    endpoints = tuple(sorted(((ip1, str(port1)), (ip2, str(port2)))))
    return protocol, endpoints


packets_by_connection = defaultdict(list)

with open(PACKET_INPUT, newline="") as file:
    for packet in csv.DictReader(file):
        ip_protocol = packet.get("ip.proto", "")
        protocol = {"6": "tcp", "17": "udp"}.get(ip_protocol)

        if protocol == "tcp":
            src_port = packet.get("tcp.srcport", "")
            dst_port = packet.get("tcp.dstport", "")
        elif protocol == "udp":
            src_port = packet.get("udp.srcport", "")
            dst_port = packet.get("udp.dstport", "")
        else:
            continue

        if not src_port or not dst_port:
            continue

        key = endpoint_key(
            protocol,
            packet["ip.src"], src_port,
            packet["ip.dst"], dst_port
        )
        packets_by_connection[key].append(packet)


with open(ZEEK_INPUT) as file:
    lines = file.readlines()

fields = next(
    line.rstrip("\n").split("\t")[1:]
    for line in lines if line.startswith("#fields")
)

output_columns = metadata + model_features

connection_count = 0
matched_count = 0

with open(OUTPUT, "w", newline="") as file:
    writer = csv.DictWriter(file, fieldnames=output_columns)
    writer.writeheader()

    for line in lines:
        if line.startswith("#") or not line.strip():
            continue

        values = line.rstrip("\n").split("\t")

        if len(values) != len(fields):
            continue

        record = dict(zip(fields, values))
        row = {}

        for column in metadata:
            row[column] = record.get(column, "")

        direct_map = {
            "Scr_port": "id.orig_p",
            "Des_port": "id.resp_p",
            "Duration": "duration",
            "Scr_bytes": "orig_bytes",
            "Des_bytes": "resp_bytes",
            "missed_bytes": "missed_bytes",
            "Scr_pkts": "orig_pkts",
            "Scr_ip_bytes": "orig_ip_bytes",
            "Des_pkts": "resp_pkts",
            "Des_ip_bytes": "resp_ip_bytes",
        }

        for feature, source in direct_map.items():
            value = number(record.get(source, ""))
            row[feature] = "" if value is None else value

        # Operational encoding based on the agreed state handling.
        # Zeek conn_state has no verified mapping to X-IIoTID's binary encoding.
        row["Conn_state"] = ""
        row["Protocol"] = record.get("proto", "")
        row["Service"] = record.get("service", "")

        if row["Service"] == "-":
            row["Service"] = ""

        protocol = str(record.get("proto", "")).lower()

        key = endpoint_key(
            protocol,
            record["id.orig_h"], record["id.orig_p"],
            record["id.resp_h"], record["id.resp_p"]
        )

        start_time = number(record.get("ts"))
        duration = number(record.get("duration"))

        matched_packets = []

        for packet in packets_by_connection.get(key, []):
            packet_time = number(packet.get("frame.time_epoch"))

            if packet_time is None or start_time is None:
                continue

            if packet_time < start_time:
                continue

            if duration is not None and packet_time > start_time + duration + 0.001:
                continue

            matched_packets.append(packet)

        if matched_packets and protocol == "tcp":
            syn_only_packets = [
                p for p in matched_packets
                if truth(p["tcp.flags.syn"])
                and not truth(p["tcp.flags.ack"])
                and not truth(p["tcp.flags.reset"])
                and not truth(p["tcp.flags.fin"])
                and not truth(p["tcp.flags.push"])
                and not truth(p["tcp.flags.urg"])
                and int(p["tcp.len"] or 0) == 0
            ]

            row["is_syn_only"] = int(
                len(syn_only_packets) == len(matched_packets)
            )

            row["Is_SYN_ACK"] = int(any(
                truth(p["tcp.flags.syn"]) and truth(p["tcp.flags.ack"])
                for p in matched_packets
            ))

            row["is_pure_ack"] = int(any(
                truth(p["tcp.flags.ack"])
                and not truth(p["tcp.flags.syn"])
                and not truth(p["tcp.flags.fin"])
                and not truth(p["tcp.flags.reset"])
                and not truth(p["tcp.flags.push"])
                and not truth(p["tcp.flags.urg"])
                and int(p["tcp.len"] or 0) == 0
                for p in matched_packets
            ))

            row["is_with_payload"] = int(any(
                int(p["tcp.len"] or 0) > 0
                for p in matched_packets
            ))

            row["FIN or RST"] = int(any(
                truth(p["tcp.flags.fin"]) or truth(p["tcp.flags.reset"])
                for p in matched_packets
            ))

            row["is_SYN_with_RST"] = int(any(
                truth(p["tcp.flags.syn"]) and truth(p["tcp.flags.reset"])
                for p in matched_packets
            ))

            row["Bad_checksum"] = int(any(
                p.get("tcp.checksum.status") == "0"
                or p.get("tcp.checksum_bad.expert", "").strip() not in ("", "-")
                for p in matched_packets
            ))

            matched_count += 1

        elif matched_packets:
            # Assign UDP feature values based on the training dataset.
            matched_count += 1

            udp_values = {
                "is_syn_only": 0,
                "Is_SYN_ACK": 0,
                "is_pure_ack": 0,
                "is_with_payload": 1,
                "FIN or RST": 0,
                "Bad_checksum": 0,
                "is_SYN_with_RST": 0
            }

            for feature, value in udp_values.items():
                row[feature] = value

        else:
            for feature in [
                "is_syn_only", "Is_SYN_ACK", "is_pure_ack",
                "is_with_payload", "FIN or RST",
                "Bad_checksum", "is_SYN_with_RST"
            ]:
                row[feature] = ""

        # Calculate verified byte and packet features.
        scr_bytes = number(row["Scr_bytes"])
        des_bytes = number(row["Des_bytes"])
        scr_ip_bytes = number(row["Scr_ip_bytes"])
        des_ip_bytes = number(row["Des_ip_bytes"])

        scr_pkts = number(row["Scr_pkts"])
        des_pkts = number(row["Des_pkts"])
        duration = number(row["Duration"])

        scr_total_bytes = (
            scr_bytes + scr_ip_bytes
            if scr_bytes is not None and scr_ip_bytes is not None
            else None
        )

        des_total_bytes = (
            des_bytes + des_ip_bytes
            if des_bytes is not None and des_ip_bytes is not None
            else None
        )

        total_bytes = (
            scr_total_bytes + des_total_bytes
            if scr_total_bytes is not None and des_total_bytes is not None
            else None
        )

        total_packets = (
            scr_pkts + des_pkts
            if scr_pkts is not None and des_pkts is not None
            else None
        )

        row["total_bytes"] = "" if total_bytes is None else total_bytes
        row["total_packet"] = "" if total_packets is None else total_packets

        row["paket_rate"] = (
            total_packets / duration
            if total_packets is not None and duration is not None and duration > 0
            else ""
        )

        row["byte_rate"] = (
            total_bytes / duration
            if total_bytes is not None and duration is not None and duration > 0
            else ""
        )

        row["Scr_packts_ratio"] = calculate_ratio(scr_pkts, total_packets)
        row["Des_pkts_ratio"] = calculate_ratio(des_pkts, total_packets)
        row["Scr_bytes_ratio"] = calculate_ratio(scr_total_bytes, total_bytes)
        row["Des_bytes_ratio"] = calculate_ratio(des_total_bytes, total_bytes)

        writer.writerow(row)
        connection_count += 1


print("Extraction completed.")
print("Connections extracted:", connection_count)
print("Connections matched with packet data:", matched_count)
print("Model features generated:", len(model_features))
print("Output file:", OUTPUT)
