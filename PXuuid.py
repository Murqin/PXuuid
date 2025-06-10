import os
import hashlib
from argon2 import PasswordHasher
from datetime import datetime
import psutil
import time
import sys
import platform
import random # Added for shuffling

# --- Argon2 KDF Configuration ---
# Carefully adjust these parameters for your server environment.
# Higher values mean more security but also more CPU/RAM consumption.
# For 'strongest IDs', consider slightly higher values if server resources allow.
# For example, memory_cost=262144 (256MB), time_cost=4 or 5
ph = PasswordHasher(time_cost=4, memory_cost=262144, parallelism=os.cpu_count() or 8, hash_len=32)
# time_cost (t): Number of iterations. Higher value, more resistance to brute-force.
# memory_cost (m): Memory consumption (in KB). Higher value, more resistance to memory-based attacks.
# parallelism (p): Number of CPU threads to use. Adjusted according to the server's core count, defaults to 8 if unavailable.
# hash_len: Length of the derived key in bytes. 32 bytes (256 bits) is sufficient.

# --- Global Security Thresholds ---
# Minimum required entropy for ID generation. This is CRITICAL for "strongest IDs".
# A typical recommended minimum for cryptographic operations is 128 bits.
MIN_REQUIRED_ENTROPY = 256 # Setting a higher threshold for absolute "strongest" IDs.

# --- Helper Functions ---
def _generate_crypto_random_bytes(length: int) -> bytes:
    """
    Generates the specified number of bytes from the operating system's
    cryptographically secure random source (os.urandom).
    This function will terminate the program if a critical error occurs (e.g., insufficient entropy
    or os.urandom not supported), as it forms the basis of security.
    """
    try:
        if length <= 0:
            raise ValueError("Length for random bytes must be positive.")
        return os.urandom(length)
    except NotImplementedError:
        print("Critical Error: os.urandom() is not supported on this system. Cannot generate secure IDs.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Critical Error: Failed to generate cryptographically random bytes: {e}", file=sys.stderr)
        sys.exit(1)

def _get_dynamic_server_data() -> dict:
    """
    Function that collects various dynamic data from the virtual server environment.
    This function is designed to be robust; any failure to retrieve critical data
    will result in an exception, preventing ID generation with incomplete data.
    """
    try:
        now = datetime.now()

        # Timestamp Data (High Precision)
        current_hour_minute = now.strftime("%H%M")
        current_second_microsecond = f"{now.second}{now.microsecond:06}"
        current_day_month = now.strftime("%d%m")
        current_year = str(now.year)
        current_timestamp_ms = int(now.timestamp() * 1000)

        # CPU Usage and Load
        cpu_load_avg = psutil.getloadavg()
        cpu_percent_total = int(psutil.cpu_percent(interval=None))

        # Memory Usage
        mem_info = psutil.virtual_memory()
        mem_percent = int(mem_info.percent)
        mem_available_mb = int(mem_info.available / (1024 * 1024))

        # Disk I/O (Read/Write Bytes)
        disk_io = psutil.disk_io_counters()
        disk_read_kb = int(disk_io.read_bytes / 1024)
        disk_write_kb = int(disk_io.write_bytes / 1024)

        # Network Activity (Sent/Received Bytes and Packet Counts)
        net_io = psutil.net_io_counters()
        net_sent_kb = int(net_io.bytes_sent / 1024)
        net_recv_kb = int(net_io.bytes_recv / 1024)
        net_packet_sent = net_io.packets_sent
        net_packet_recv = net_io.packets_recv

        # Process Count and Thread Count
        process_count = len(psutil.pids())
        thread_count = 0
        for p in psutil.process_iter(['num_threads']):
            try:
                if 'num_threads' in p.info and p.info['num_threads'] is not None:
                    thread_count += p.info['num_threads']
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass # Skip processes that might have terminated or are inaccessible

        # System Boot Time
        boot_time_seconds = int(psutil.boot_time())

        # Disk Usage Percentage
        disk_usage_percent = int(psutil.disk_usage('/').percent)

        # Entropy Pool Status (Linux-specific, returns -1 on other OS)
        entropy_avail = -1
        entropy_path = '/proc/sys/kernel/random/entropy_avail'
        if os.path.exists(entropy_path):
            with open(entropy_path, 'r') as f:
                entropy_avail = int(f.read().strip())
        # If entropy_avail remains -1 on Linux, this indicates a read failure which is a problem.
        # However, we only check for minimum threshold later.

        # Uptime of the system in seconds
        system_uptime = int(time.time() - psutil.boot_time())

        # Number of logged in users
        logged_in_users_count = len(psutil.users())

        # Open files count (can be resource intensive for many processes, handle errors)
        open_files_count = 0
        for p in psutil.process_iter(['num_fds']):
            try:
                if 'num_fds' in p.info and p.info['num_fds'] is not None:
                    open_files_count += p.info['num_fds']
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # System-wide CPU times (user, system, idle)
        cpu_times = psutil.cpu_times()
        cpu_times_user = int(cpu_times.user * 1000) # milliseconds
        cpu_times_system = int(cpu_times.system * 1000) # milliseconds
        cpu_times_idle = int(cpu_times.idle * 1000) # milliseconds

        # Platform information (adds to initial entropy, less dynamic but valuable)
        platform_system = platform.system()
        platform_release = platform.release()
        platform_version = platform.version()
        platform_machine = platform.machine()
        platform_node = platform.node() # Hostname can also add unique entropy

        return {
            "hour_minute": current_hour_minute,
            "second_microsecond": current_second_microsecond,
            "day_month": current_day_month,
            "year": current_year,
            "timestamp_ms": current_timestamp_ms,
            "cpu_load_avg_1min": int(cpu_load_avg[0] * 1000),
            "cpu_percent_total": cpu_percent_total,
            "mem_percent": mem_percent,
            "mem_available_mb": mem_available_mb,
            "disk_read_kb": disk_read_kb,
            "disk_write_kb": disk_write_kb,
            "net_sent_kb": net_sent_kb,
            "net_recv_kb": net_recv_kb,
            "net_packet_sent": net_packet_sent,
            "net_packet_recv": net_packet_recv,
            "process_count": process_count,
            "thread_count": thread_count,
            "boot_time_seconds": boot_time_seconds,
            "disk_usage_percent": disk_usage_percent,
            "entropy_avail": entropy_avail,
            "system_uptime": system_uptime,
            "logged_in_users_count": logged_in_users_count,
            "open_files_count": open_files_count,
            "cpu_times_user": cpu_times_user,
            "cpu_times_system": cpu_times_system,
            "cpu_times_idle": cpu_times_idle,
            "platform_system": platform_system,
            "platform_release": platform_release,
            "platform_version": platform_version,
            "platform_machine": platform_machine,
            "platform_node": platform_node
        }
    except Exception as e:
        # Any failure in collecting dynamic data is critical for "strongest IDs".
        raise RuntimeError(f"Failed to collect critical dynamic server data: {e}")

def _process_user_phrase_naclception(user_phrase: str) -> bytes:
    """
    Splits the user-provided text into random chunks, salts each chunk, and processes it with KDF.
    This part represents the user's entropy contribution. Ensures a minimum random contribution
    even if the user phrase is empty.
    """
    phrase_bytes = user_phrase.encode('utf-8') if user_phrase else b''
    processed_sub_parts = []
    phrase_length = len(phrase_bytes)

    MIN_BLOCK_SIZE = 16
    MAX_BLOCK_SIZE = 64
    RANGE_BLOCK_SIZE = MAX_BLOCK_SIZE - MIN_BLOCK_SIZE + 1

    current_pos = 0
    while current_pos < phrase_length:
        random_block_size = (_generate_crypto_random_bytes(1)[0] % RANGE_BLOCK_SIZE) + MIN_BLOCK_SIZE
        sub_part_bytes = phrase_bytes[current_pos : current_pos + random_block_size]
        current_pos += random_block_size

        # If the part is not a full block size, pad with cryptographically random bytes
        if len(sub_part_bytes) < random_block_size:
            padding_needed = random_block_size - len(sub_part_bytes)
            sub_part_bytes += _generate_crypto_random_bytes(padding_needed)

        salt_for_sub_part = _generate_crypto_random_bytes(16)
        kdf_input_for_sub_part = sub_part_bytes + salt_for_sub_part

        try:
            argon2_sub_hash_string = ph.hash(kdf_input_for_sub_part)
            processed_sub_parts.append(argon2_sub_hash_string.encode('utf-8'))
        except Exception as e:
            # If Argon2 fails for user input, it's a critical error for "strongest IDs"
            raise RuntimeError(f"A problem occurred while processing user input sub-part with Argon2: {e}")

    # If the user entered an empty phrase, we MUST still provide a strong random contribution.
    if not processed_sub_parts and not user_phrase:
        # Generate a large chunk of random bytes to hash for entropy contribution
        random_input_for_hash = _generate_crypto_random_bytes(ph.hash_len * 2) # Use more random bytes
        try:
            processed_sub_parts.append(ph.hash(random_input_for_hash).encode('utf-8'))
        except Exception as e:
            raise RuntimeError(f"A problem occurred while generating Argon2 hash for empty user phrase: {e}")

    return b''.join(processed_sub_parts)

def generate_secure_server_id(user_provided_phrase: str = "") -> str:
    """
    Secure ID generation algorithm suitable for server-side virtual machine environments.
    Only generates an ID if strict entropy and data collection criteria are met.
    The final ID is a 24-character SHA-256 output, separated by hyphens in 4-character blocks,
    in all UPPERCASE format.
    """
    start_time = time.perf_counter()

    try:
        system_data = _get_dynamic_server_data()

        # --- Strict Entropy Check (CRITICAL for "strongest IDs") ---
        # Only perform this check if on Linux where entropy_avail is supported.
        if system_data['entropy_avail'] != -1 and system_data['entropy_avail'] < MIN_REQUIRED_ENTROPY:
            raise RuntimeError(f"Insufficient system entropy ({system_data['entropy_avail']} bits). "
                               f"Required: {MIN_REQUIRED_ENTROPY} bits. Cannot generate strongest ID.")
        elif system_data['entropy_avail'] == -1 and platform.system() == "Linux":
            # If on Linux and entropy_avail couldn't be read, it's also a problem.
            raise RuntimeError("Could not read /proc/sys/kernel/random/entropy_avail. Cannot verify entropy level.")
        # For non-Linux systems, we rely solely on os.urandom()'s robustness and assume sufficient entropy.


        # Breaking down Input Data (as string) - Ensure all new fields are included
        parts_data_str = [
            str(system_data['hour_minute']),
            str(system_data['second_microsecond']),
            str(system_data['day_month']),
            str(system_data['year']),
            str(system_data['timestamp_ms']),
            str(system_data['cpu_load_avg_1min']),
            str(system_data['cpu_percent_total']),
            str(system_data['mem_percent']),
            str(system_data['mem_available_mb']),
            str(system_data['disk_read_kb']),
            str(system_data['disk_write_kb']),
            str(system_data['net_sent_kb']),
            str(system_data['net_recv_kb']),
            str(system_data['net_packet_sent']),
            str(system_data['net_packet_recv']),
            str(system_data['process_count']),
            str(system_data['thread_count']),
            str(system_data['boot_time_seconds']),
            str(system_data['disk_usage_percent']),
            str(system_data['entropy_avail']), # Include entropy_avail in hash calculation too
            str(system_data['system_uptime']),
            str(system_data['logged_in_users_count']),
            str(system_data['open_files_count']),
            str(system_data['cpu_times_user']),
            str(system_data['cpu_times_system']),
            str(system_data['cpu_times_idle']),
            system_data['platform_system'],
            system_data['platform_release'],
            system_data['platform_version'],
            system_data['platform_machine'],
            system_data['platform_node']
        ]

        processed_parts_hashes = []

        # Salting and Processing Each Part Individually with KDF (Argon2)
        for part_data_str in parts_data_str:
            salt_bytes = _generate_crypto_random_bytes(16)
            kdf_input = part_data_str.encode('utf-8') + salt_bytes

            try:
                argon2_hash_string = ph.hash(kdf_input)
                processed_parts_hashes.append(argon2_hash_string.encode('utf-8'))
            except Exception as e:
                raise RuntimeError(f"A problem occurred during Argon2 processing for system data part: {e}")

        # Processing User-Provided Random Phrase (Naclception Layer)
        processed_user_data = _process_user_phrase_naclception(user_provided_phrase)

        # Combining All Processed Parts (System and User)
        # Shuffle the order of concatenation of processed_parts_hashes for more unpredictability.
        random.shuffle(processed_parts_hashes)

        final_combined_data = b''.join(processed_parts_hashes) + processed_user_data

        # Final Hashing (with SHA-256)
        final_raw_id = hashlib.sha256(final_combined_data).hexdigest()

        # Shortening and Formatting Step:
        shortened_id = final_raw_id[:24]
        formatted_id = '-'.join([shortened_id[i:i+4] for i in range(0, len(shortened_id), 4)]).upper()

        end_time = time.perf_counter()
        print(f"ID generation time: {((end_time - start_time) * 1000):.2f} ms")

        return formatted_id

    except RuntimeError as e:
        print(f"ID Generation Failed: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"An unexpected error occurred during ID generation: {e}", file=sys.stderr)
        return None

# --- Main Program Block ---
if __name__ == "__main__":
    print("### Secure Server ID Generator (Virtual Machine Compatible) ###")
    print("------------------------------------------------------------------")
    print("This program generates ONLY the strongest, cryptographically secure IDs from the virtual machine's current state.")
    print("It enforces strict entropy requirements and will not generate an ID if conditions are not met.")
    print("An optional random phrase provided by the user also contributes to the ID.")
    print(f"Minimum required system entropy for ID generation: {MIN_REQUIRED_ENTROPY} bits (Linux only).")
    print("Generated IDs will be in 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA' format and UPPERCASE.")
    print("------------------------------------------------------------------")

    user_phrase = input("Please enter a random word/phrase to contribute to the ID (you can leave it blank): ")

    num_ids_to_generate = 1
    try:
        user_input_num = input("How many IDs would you like to generate? (Default: 1, 'q' to quit): ")
        if user_input_num.lower() == 'q':
            print("Exiting...")
            sys.exit(0)
        num_ids_to_generate = int(user_input_num)
        if num_ids_to_generate <= 0:
            raise ValueError
    except ValueError:
        print("Invalid input. 1 ID will be generated by default.")
        num_ids_to_generate = 1

    generated_ids = []
    for i in range(num_ids_to_generate):
        print(f"\nAttempting to generate ID ({i+1}/{num_ids_to_generate})...")
        current_id = generate_secure_server_id(user_provided_phrase=user_phrase)
        if current_id:
            print(f"Successfully Generated ID: {current_id}")
            generated_ids.append(current_id)
        else:
            print(f"ID generation attempt ({i+1}/{num_ids_to_generate}) failed due to insufficient security conditions.")

        if num_ids_to_generate > 1 and i < num_ids_to_generate - 1:
            # Short wait for slightly different dynamic data for multiple IDs, if successful
            if current_id:
                time.sleep(0.1)

    print("\n------------------------------------------------------------------")
    if generated_ids:
        unique_ids = set(generated_ids)
        if len(unique_ids) == len(generated_ids):
            print("All successfully generated IDs are unique (expected behavior).")
        else:
            print(f"Warning: {len(unique_ids)} out of {len(generated_ids)} successfully generated IDs are unique. "
                    "There might be duplicate IDs. Check entropy source or parameters.")
    else:
        print("No IDs could be generated under the strict security conditions.")

    print("Program Terminated.")
