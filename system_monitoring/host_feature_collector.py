import csv
import re
import time
import os
import subprocess
import statistics
import psutil

from datetime import datetime
from pathlib import Path


OUTPUT = Path("host_features_live.csv")
WATCH_ROOT = Path.home()
SAMPLES = 300
INTERVAL = 1

FEATURE_COLUMNS = [
    "Avg_user_time", "Std_user_time",
    "Avg_nice_time", "Std_nice_time",
    "Avg_system_time", "Std_system_time",
    "Avg_iowait_time", "Std_iowait_time",
    "Avg_ideal_time", "Std_ideal_time",
    "Avg_tps", "Std_tps",
    "Avg_rtps", "Std_rtps",
    "Avg_wtps", "Std_wtps",
    "Avg_ldavg_1", "Std_ldavg_1",
    "Avg_kbmemused", "Std_kbmemused",
    "Avg_num_Proc/s", "Std_num_proc/s",
    "Avg_num_cswch/s", "std_num_cswch/s",
    "Login_attempt",
    "Succesful_login",
    "File_activity",
    "Process_activity",
    "read_write_physical.process",
    "is_privileged"
]


def run_sar(option):
    return subprocess.Popen(
        ["sar", option, "1", str(SAMPLES)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )


def sar_rows(output):
    rows = []

    for line in output.splitlines():
        parts = line.split()

        if not parts:
            continue

        if not re.fullmatch(r"\d{2}:\d{2}:\d{2}", parts[0]):
            continue

        index = 1

        # Skip AM/PM if present.
        if index < len(parts) and parts[index].upper() in ("AM", "PM"):
            index += 1

        # Skip timezone, such as IST or UTC.
        if index < len(parts) and parts[index].isalpha() and parts[index] != "all":
            index += 1

        # Skip CPU label when present.
        if index < len(parts) and parts[index] == "all":
            index += 1

        try:
            rows.append([float(value) for value in parts[index:]])
        except ValueError:
            continue

    return rows

def avg_std(values):
    if len(values) < 2:
        raise RuntimeError("Insufficient samples")

    return statistics.mean(values), statistics.stdev(values)


def file_snapshot():
    snapshot = {}

    excluded_dir_names = {
        ".cache",
        ".local",
        ".venv",
        "venv",
        "__pycache__",
        ".git",
        "node_modules",
        "network_logs"
    }

    # Keep generated experiment evidence separate from monitored activity.
    excluded_paths = {
        WATCH_ROOT / "Desktop" / "apt-detection-project"
        / "experiment_1" / "evidence"
    }

    for current_root, dirs, files in os.walk(
        WATCH_ROOT,
        topdown=True,
        followlinks=False
    ):
        current_path = Path(current_root)

        # Avoid scanning noisy or generated directories.
        dirs[:] = [
            dirname for dirname in dirs
            if dirname not in excluded_dir_names
            and (current_path / dirname).resolve() not in excluded_paths
        ]

        for filename in files:
            path = current_path / filename

            try:
                info = path.stat()

                snapshot[str(path)] = (
                    info.st_mtime_ns,
                    info.st_size
                )

            except OSError:
                continue

    return snapshot

def process_snapshot():
    snapshot = {}

    for proc in psutil.process_iter(["pid", "name"]):
        try:
            pid = proc.info["pid"]
            name = proc.info["name"] or ""

            # Do not count the collector's own SAR processes.
            if name.lower() in ("sar", "sadc"):
                continue

            if pid != os.getpid():
                snapshot[pid] = name

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return snapshot


def read_journal(arguments):
    result = subprocess.run(
        ["journalctl"] + arguments +
        ["--no-pager", "-o", "cat"],
        capture_output=True,
        text=True,
        timeout=10
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Could not read system journal: " + result.stderr.strip()
        )

    return result.stdout


def collect_activity(start_time, end_time):
    since = start_time.isoformat(timespec="seconds")
    until = end_time.isoformat(timespec="seconds")

    ssh_logs = read_journal([
        "-u", "ssh",
        "--since", since,
        "--until", until
    ])

    sudo_logs = read_journal([
        "_COMM=sudo",
        "--since", since,
        "--until", until
    ])

    successful_login = bool(re.search(
        r"Accepted (password|publickey)",
        ssh_logs,
        re.IGNORECASE
    ))

    login_attempt = bool(re.search(
        r"Accepted (password|publickey)|Failed password|Invalid user|authentication failure",
        ssh_logs,
        re.IGNORECASE
    ))

    sudo_commands = re.findall(
        r"COMMAND=(.+)",
        sudo_logs
    )

    return login_attempt, successful_login, bool(sudo_commands)


def collect():
    print("\nCollecting 300-second window...")

    start_time = datetime.now().astimezone()

    commands = ["-u", "-r", "-q", "-w", "-b"]
    processes = [run_sar(option) for option in commands]

    previous_files = file_snapshot()
    previous_processes = process_snapshot()

    file_activity = False
    process_activity = False

    # Monitor files and processes during the SAR collection window.
    for _ in range(SAMPLES):
        time.sleep(INTERVAL)

        current_files = file_snapshot()
        current_processes = process_snapshot()

        if current_files != previous_files:
            file_activity = True

        if current_processes.keys() - previous_processes.keys():
            process_activity = True

        previous_files = current_files
        previous_processes = current_processes

    end_time = datetime.now().astimezone()

    outputs = []

    for proc in processes:
        stdout, stderr = proc.communicate()

        if proc.returncode != 0:
            raise RuntimeError(stderr or "SAR failed")

        outputs.append(sar_rows(stdout))

    cpu, memory, load, process, disk = outputs

    expected_columns = {
        "-u": 6,
        "-r": 3,
        "-q": 3,
        "-w": 2,
        "-b": 7
    }

    for name, rows in zip(commands, outputs):
        if len(rows) < 2:
            raise RuntimeError(
                f"Not enough SAR samples for {name}: {len(rows)}"
            )

        if any(
            len(row) < expected_columns[name]
            for row in rows
        ):
            raise RuntimeError(
                f"Unexpected SAR columns for {name}: {rows[:2]}"
            )

    features = {}

    # 1. CPU features
    cpu_columns = {
        "user_time": 0,
        "nice_time": 1,
        "system_time": 2,
        "iowait_time": 3,
        "ideal_time": 5
    }

    for name, index in cpu_columns.items():
        values = [row[index] for row in cpu]

        features[f"Avg_{name}"], features[f"Std_{name}"] = avg_std(values)

    # 2. Disk features from SAR -b
    disk_columns = {
        "tps": 0,
        "rtps": 1,
        "wtps": 2
    }

    for name, index in disk_columns.items():
        values = [row[index] for row in disk]

        features[f"Avg_{name}"], features[f"Std_{name}"] = avg_std(values)

    # 3. Load average
    values = [row[2] for row in load]
    features["Avg_ldavg_1"], features["Std_ldavg_1"] = avg_std(values)

    # 4. Memory usage
    values = [row[2] for row in memory]
    features["Avg_kbmemused"], features["Std_kbmemused"] = avg_std(values)

    # 5. Process creation rate
    values = [row[0] for row in process]
    features["Avg_num_Proc/s"], features["Std_num_proc/s"] = avg_std(values)

    # 6. Context switch rate
    values = [row[1] for row in process]
    features["Avg_num_cswch/s"], features["std_num_cswch/s"] = avg_std(values)

    # 7. Login activity
    login_attempt, successful_login, sudo_activity = collect_activity(
        start_time, end_time
    )

    features["Login_attempt"] = int(login_attempt)
    features["Succesful_login"] = int(successful_login)

    # 8. File and process activity
    features["File_activity"] = int(file_activity)
    features["Process_activity"] = int(process_activity)

    # 9. No physical-process telemetry is available on this setup.
    # The trained pipeline's SimpleImputer handles this missing value.
    features["read_write_physical.process"] = float("nan")

    # 10. Privileged activity is approximated by correlating a sudo
    # command with a monitored file/process event in this time window.
    features["is_privileged"] = int(
        sudo_activity and (file_activity or process_activity)
    )

    # Verify exact model feature order.
    if list(features.keys()) != FEATURE_COLUMNS:
        raise RuntimeError("Feature names or order do not match the model")

    features["timestamp"] = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )

    fieldnames = FEATURE_COLUMNS + ["timestamp"]

    new_file = not OUTPUT.exists() or OUTPUT.stat().st_size == 0

    with OUTPUT.open("a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)

        if new_file:
            writer.writeheader()

        writer.writerow(features)

    print("Host features collected:", len(FEATURE_COLUMNS))
    print("Login attempt:", features["Login_attempt"])
    print("Successful login:", features["Succesful_login"])
    print("File activity:", features["File_activity"])
    print("Process activity:", features["Process_activity"])
    print("Privileged activity:", features["is_privileged"])
    print("Saved to:", OUTPUT)
    return features


if __name__ == "__main__":
    print("Integrated host feature collector started.")
    print("Output:", OUTPUT)
    print("Press Ctrl+C to stop.")

    try:
        while True:
            collect()

    except KeyboardInterrupt:
        print("\nCollection stopped.")

    except Exception as error:
        print("\nCollector stopped due to error:", error)
