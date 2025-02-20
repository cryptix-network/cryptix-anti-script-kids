import psutil
import subprocess
import time
import curses
from collections import Counter, defaultdict

MAX_CONNECTIONS = 20
MAX_CONNECTIONS_PER_SECOND = 20 
TIME_LIMIT = 3  
TIME_WINDOW = 0.5  
SYN_THRESHOLD = 20
UDP_THRESHOLD = 50
ZERO_BYTE_THRESHOLD = 10
MIN2_REQUEST = 1000
BLOCK_COOLDOWN = 30 
TIME_WINDOW_LONG = 10  
REQUESTS_THRESHOLD = 50

SUSTAINED_CONNECTION_LIMIT = 40  
SUSTAINED_CONNECTION_DURATION = 30 

LOG_FILE = "ddos_block_log.txt"

ip_block_counter = {}
ip_sustained_connections = defaultdict(float)
port_counter = {80: 0, 443: 0, 8000: 0, 8001: 0, 8080: 0, 8443: 0}
ip_connections_last_30s = defaultdict(int)
syn_counter = defaultdict(int)
udp_counter = defaultdict(int)
zero_byte_counter = defaultdict(int)
ip_request_time = defaultdict(list)  
ip_request_time_2min = defaultdict(list)  

blocked_ips = {}

def log_blocked_ip(ip):
    """Log the blocked IP to a file."""
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Blocked IP: {ip}\n")
    print(f"Blocked IP: {ip}")

def track_sustained_connections(ip, connection_count):
    """Track connections over time to detect long-running DDoS attacks."""
    current_time = time.time()
    if connection_count > SUSTAINED_CONNECTION_LIMIT:
        if ip not in ip_sustained_connections:
            ip_sustained_connections[ip] = current_time  
        elif current_time - ip_sustained_connections[ip] > SUSTAINED_CONNECTION_DURATION:
            print(f"IP {ip} has more than {SUSTAINED_CONNECTION_LIMIT} connections for more than {SUSTAINED_CONNECTION_DURATION} seconds. Blocking it.")
            block_ip(ip)
            del ip_sustained_connections[ip]
    else:
        if ip in ip_sustained_connections:
            del ip_sustained_connections[ip]  

def block_ip(ip):
    """Block IP if it exceeds any threshold."""
    current_time = time.time()

    if ip in blocked_ips:
        last_blocked = blocked_ips[ip]
        if current_time - last_blocked < BLOCK_COOLDOWN:
            print(f"IP {ip} is on Cooldown")
            return

    try:
        command = f'sudo iptables -A INPUT -s {ip} -j DROP'
        subprocess.run(command, shell=True, check=True)
        print(f"Blocked IP: {ip}")
        log_blocked_ip(ip)
        blocked_ips[ip] = current_time
        
        if ip in ip_request_time:
            del ip_request_time[ip]
        if ip in ip_request_time_2min:
            del ip_request_time_2min[ip]
        if ip in ip_connections_last_30s:
            del ip_connections_last_30s[ip]
        
        print(f"IP {ip} has been removed from tracking lists.")

    except Exception as e:
        print(f"Error blocking IP {ip}: {e}")

def get_active_connections():
    """Retrieve active network connections."""
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'ESTABLISHED' and (conn.laddr.port in port_counter.keys()):
            if conn.raddr.ip != "127.0.0.1" and conn.raddr.ip != "::1":
                connections.append((conn.raddr.ip, conn.laddr.port))
                port_counter[conn.laddr.port] += 1
    return connections

def group_ips_by_similarity(connections):
    """Group IPs by the first 3 octets."""
    grouped_ips = defaultdict(int)
    for ip, port in connections:
        ip_prefix = '.'.join(ip.split('.')[:3])
        grouped_ips[ip_prefix] += 1
    return grouped_ips

def track_connections_per_second(ip):
    """Track requests per second for each IP."""
    current_time = time.time()

    # Filter old timestamps 
    ip_request_time[ip] = [timestamp for timestamp in ip_request_time[ip] if current_time - timestamp <= TIME_WINDOW]
    ip_request_time_2min[ip] = [timestamp for timestamp in ip_request_time_2min[ip] if current_time - timestamp <= 120]  

    
    ip_request_time[ip].append(current_time)
    ip_request_time_2min[ip].append(current_time)

    requests_in_last_10_sec = len([timestamp for timestamp in ip_request_time[ip] if current_time - timestamp <= TIME_WINDOW_LONG])

    if requests_in_last_10_sec > REQUESTS_THRESHOLD:
        print(f"IP {ip} exceeded {REQUESTS_THRESHOLD} requests per second for more than {TIME_WINDOW_LONG} seconds, blocking.")
        block_ip(ip)

def monitor_synthetic_traffic(ip, syn_count, udp_count):
    """Monitor SYN and UDP flood attacks."""
    if syn_count > SYN_THRESHOLD:
        print(f"SYN Flood Detected from IP {ip}, blocking.")
        block_ip(ip)
    elif udp_count > UDP_THRESHOLD:
        print(f"UDP Flood Detected from IP {ip}, blocking.")
        block_ip(ip)

def monitor_zero_byte(ip, byte_count):
    """Monitor Zero Byte Attacks."""
    if byte_count == 0:
        print(f"Zero Byte Attack Detected from IP {ip}, blocking.")
        block_ip(ip)

def monitor_connections(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(TIME_LIMIT * 1000)

    max_width = curses.COLS - 2
    max_height = curses.LINES - 1
    row = 0

    ascii_art = """
   _____                  _   _      
  / ____|                | | (_)     
 | |     _ __ _   _ _ __ | |_ ___  __
 | |    | '__| | | | '_ \| __| \ \/ /
 | |____| |  | |_| | |_) | |_| |>  < 
  \_____|_|   \__, | .__/ \__|_/_/\_\
               __/ | |               
              |___/|_|               
    """
    
    stdscr.addstr(row, 0, ascii_art)
    row += 6  
    stdscr.refresh() 
    time.sleep(2)

    while True:
        for port in port_counter:
            port_counter[port] = 0

        connections = get_active_connections()
        ip_counts = Counter([ip for ip, port in connections])

        for ip, count in ip_counts.items():
            ip_connections_last_30s[ip] += count
            track_connections_per_second(ip) 
            track_sustained_connections(ip, count) 

        grouped_ips = group_ips_by_similarity(connections)

        stdscr.clear()

        stdscr.addstr(row, 0, "Connection counts per port:")
        row += 1
        for port, count in port_counter.items():
            text = f"Port {port}: {count} connections"
            if row < max_height:
                stdscr.addstr(row, 0, text[:max_width])
                row += 1
            else:
                row = 0
                stdscr.clear()
                stdscr.addstr(row, 0, "Connection counts per port:")
                row += 1
                stdscr.refresh()
                break

        if row < max_height:
            stdscr.addstr(row, 0, "Grouped IPs by similarity (first 3 octets):")
            row += 1
        for ip_prefix, count in grouped_ips.items():
            text = f"IP Group {ip_prefix}: {count} connections"
            if row < max_height:
                stdscr.addstr(row, 0, text[:max_width])
                row += 1
            else:
                row = 0
                stdscr.clear()
                stdscr.addstr(row, 0, "Grouped IPs by similarity (first 3 octets):")
                row += 1
                stdscr.refresh()
                break

        if row < max_height:
            stdscr.addstr(row, 0, "SYN Flood Monitoring:")
            row += 1
        for ip, count in syn_counter.items():
            if count > SYN_THRESHOLD:
                text = f"SYN Attack Detected from {ip}: {count} packets"
                if row < max_height:
                    stdscr.addstr(row, 0, text[:max_width])
                    row += 1
            else:
                syn_counter[ip] = 0

        if row < max_height:
            stdscr.addstr(row, 0, "UDP Flood Monitoring:")
            row += 1
        for ip, count in udp_counter.items():
            if count > UDP_THRESHOLD:
                text = f"UDP Flood Detected from {ip}: {count} packets"
                if row < max_height:
                    stdscr.addstr(row, 0, text[:max_width])
                    row += 1
            else:
                udp_counter[ip] = 0

        if row < max_height:
            stdscr.addstr(row, 0, "0-Byte Attack Monitoring:")
            row += 1
        for ip, count in zero_byte_counter.items():
            if count > ZERO_BYTE_THRESHOLD:
                text = f"0-Byte Attack Detected from {ip}: {count} packets"
                if row < max_height:
                    stdscr.addstr(row, 0, text[:max_width])
                    row += 1
            else:
                zero_byte_counter[ip] = 0

        for ip, count in ip_counts.items():
            if count > MAX_CONNECTIONS:
                if row < max_height:
                    text = f"IP {ip} exceeded the connection limit ({count} connections). Blocking it..."
                    stdscr.addstr(row, 0, text[:max_width])
                    block_ip(ip)
                    row += 1
                else:
                    row = 0
                    stdscr.clear()
                    stdscr.addstr(row, 0, "IP Blocked:")
                    row += 1
                    stdscr.refresh()
                    break

        if row < max_height:
            stdscr.addstr(row, 0, "Top 5 Dangerous IPs (Most Connections in the Last 30 Seconds):")
            row += 1
        top_5_ips = sorted(ip_connections_last_30s.items(), key=lambda item: item[1], reverse=True)[:5]
        for ip, count in top_5_ips:
            if row < max_height:
                text = f"IP: {ip}, Connections: {count}"
                stdscr.addstr(row, 0, text[:max_width])
                row += 1
            else:
                break

        if row < max_height:
            stdscr.addstr(row, 0, "Top 5 IPs with Most Requests per Second (Last 30 seconds):")
            row += 1
     
        ip_requests_per_second = {ip: len(requests) / TIME_WINDOW for ip, requests in ip_request_time.items()}
        top_5_requests_ips = sorted(ip_requests_per_second.items(), key=lambda item: item[1], reverse=True)[:5]
        for ip, rps in top_5_requests_ips:
            if row < max_height:
                text = f"IP: {ip}, Requests per second: {rps:.2f}"
                stdscr.addstr(row, 0, text[:max_width])
                row += 1
            else:
                break

        if row < max_height:
            stdscr.addstr(row, 0, "Top 5 IPs with Most Requests in the Last 2 Minutes:")
            row += 1
     
        # Ensure ip_request_time_2min has data
        if not ip_request_time_2min:
            stdscr.addstr(row, 0, "No IPs with requests in the last 2 minutes.")
            row += 1
        else:
            ip_requests_last_2min = {ip: len(requests) for ip, requests in ip_request_time_2min.items()}
            top_5_requests_2min_ips = sorted(ip_requests_last_2min.items(), key=lambda item: item[1], reverse=True)[:5]

            stdscr.addstr(row, 0, "Top 5 IPs with the most requests in the last 2 minutes:")
            row += 1

            for ip, count in top_5_requests_2min_ips:
                text = f"IP: {ip}, Requests: {count}"
                stdscr.addstr(row, 0, text[:max_width])
                row += 1

                if ip not in blocked_ips and count > MIN2_REQUEST:
                    recent_requests = len(ip_request_time[ip])  
                    if recent_requests < (MIN2_REQUEST * 0.1):  
                        continue  

                    block_message = f"Blocking IP {ip} for {count} requests in the last 2 minutes."
                    stdscr.addstr(row, 0, block_message[:max_width])
                    row += 1

                    if count > MIN2_REQUEST * 3:
                        escalation = f"⚠️ HARD BLOCK: {ip} has over {count} requests!"
                    elif count > MIN2_REQUEST * 2:
                        escalation = f"⚠️ WARNING: {ip} is approaching critical threshold!"
                    else:
                        escalation = f"🚨 ALERT: {ip} exceeded the threshold!"

                    stdscr.addstr(row, 0, escalation[:max_width])
                    row += 1

                    block_ip(ip)

        stdscr.refresh()

if __name__ == "__main__":
    curses.wrapper(monitor_connections)
