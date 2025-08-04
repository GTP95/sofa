import subprocess
import psutil
import time
from threading import Thread

# Define commands for each target
commands = [
    "python Armchair.py --input auto --count 100 AES",
    "python Armchair.py --input auto --count 100 ASCON",
    "python Armchair.py --input auto --count 100 KECCAK",
]


# Function to monitor resources across all processes
def monitor_resources(process):
    global peak_cpu, peak_ram
    peak_cpu = 0
    peak_ram = 0
    cpu = 0
    ram = 0
    while process.poll() is None:  # While the process is running
        try:
            proc = psutil.Process(process.pid)
            # Get all child processes
            children = proc.children(recursive=True) + [proc]
            cpu = sum(p.cpu_percent(interval=0.1) for p in children) / len(children)
            ram = sum(p.memory_info().rss for p in children) / (
                1024 * 1024
            )  # RAM in MB
            peak_cpu = max(peak_cpu, cpu)
            peak_ram = max(peak_ram, ram)
        except psutil.NoSuchProcess:
            break


# Function to execute a command with retries
def execute_with_retries(cmd, max_retries=5):
    retries = 0
    while retries < max_retries:
        try:
            print(f"Running command: {cmd} (Attempt {retries + 1}/{max_retries})")
            start_time = time.time()

            # Start the subprocess
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )

            # Start monitoring resources
            monitoring_thread = Thread(target=monitor_resources, args=(process,))
            monitoring_thread.start()

            # Wait for the process to complete
            _, stderr = process.communicate()
            end_time = time.time()

            # Wait for monitoring thread to finish
            monitoring_thread.join()

            # Check if the process succeeded
            if process.returncode == 0:
                elapsed_time = end_time - start_time
                return {
                    "command": cmd,
                    "elapsed_time": elapsed_time,
                    "peak_cpu": peak_cpu,
                    "peak_ram": peak_ram,
                    "error": None,
                }
            else:
                print(
                    f"Command failed with return code {process.returncode}. Retrying..."
                )
                retries += 1
        except Exception as e:
            print(f"Error occurred: {e}. Retrying...")
            retries += 1

    print(f"Command failed after {max_retries} attempts: {cmd}")
    return {
        "command": cmd,
        "elapsed_time": None,
        "peak_cpu": None,
        "peak_ram": None,
        "error": stderr.strip() if stderr else "Unknown error.",
    }


# Run each command and monitor performance
results = []
for cmd in commands:
    result = execute_with_retries(cmd)
    results.append(result)

# Print summary
print("\nExecution Summary:")
for result in results:
    print(f"Command: {result['command']}")
    elapsed_time = result["elapsed_time"] or None

    if elapsed_time:
        minutes = int(elapsed_time // 60)
        seconds = int(elapsed_time % 60)
        milliseconds = int((elapsed_time - int(elapsed_time)) * 1000)
        print(
            f"Elapsed Time: {minutes} minutes, {seconds} seconds, {milliseconds} milliseconds"
        )
    else:
        print("Elapsed Time: N/A")
    print(
        f"Peak CPU Usage: {result['peak_cpu']:.2f}%"
        if result["peak_cpu"]
        else "Peak CPU Usage: N/A"
    )
    print(
        f"Peak RAM Usage: {result['peak_ram']:.2f} MB"
        if result["peak_ram"]
        else "Peak RAM Usage: N/A"
    )
    if result["error"]:
        print(f"Error: {result['error']}")
    print("-" * 50)
