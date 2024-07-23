import socket
import struct
import time
from ipaddress import ip_network, ip_address
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 0.2
CHALLENGE_PACKET = b'\xFF\xFF\xFF\xFF\x55\xFF\xFF\xFF\xFF'
QUERY_PACKET = b'\xFF\xFF\xFF\xFF\x54Source Engine Query\x00'
VALID_SERVERS_FILE = 'validservers.txt'
MAX_THREADS = 25

def remove_duplicates(filename):
    try:
        with open(filename, 'r') as file:
            lines = file.readlines()
        unique_lines = list(set(lines))
        with open(filename, 'w') as file:
            file.writelines(unique_lines)
        print(f"Removed duplicates from {filename}.")
    except Exception as e:
        print(f"Failed to process {filename}: {e}")

def send_query_packet(sock, packet_data, server_address):
    sock.sendto(packet_data, server_address)

def receive_response(sock):
    try:
        data, _ = sock.recvfrom(4096)
        return data
    except socket.timeout:
        return None

def query_server_info(ip, port=27015):
    server_address = (ip, port)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        send_query_packet(sock, QUERY_PACKET, server_address)
        response = receive_response(sock)
        
        if response:
            header, = struct.unpack('B', response[4:5])
            if header == 0x49:
                print(f"\033[92mServer at {ip}:{port} is a valid Valve Source server.\033[0m")
                try:
                    with open(VALID_SERVERS_FILE, 'a') as f:
                        f.write(f"{ip}:{port}\n")
                        print(f"Successfully wrote {ip}:{port} to {VALID_SERVERS_FILE}")
                except Exception as e:
                    print(f"Failed to write to file: {e}")
                return True
        else:
            print(f"\033[91mServer at {ip}:{port} is not a valid Valve Source server.\033[0m")
    return False

def ip_range_to_list(start_ip, end_ip):
    ip_list = [str(ip_address(ip)) for ip in range(int(ip_address(start_ip)), int(ip_address(end_ip)) + 1)]
    print(f"Converted IP range {start_ip} - {end_ip} to {len(ip_list)} IP addresses.")
    return ip_list

def scan_ip(ip):
    for port in range(27010, 27080):
        if query_server_info(ip, port):
            query_player_list(ip, port)
        time.sleep(0.0001)

def scan_ips(ip_list):
    total_ips = 0
    all_ips = []
    valid_ips = set()
    
    try:
        with open(VALID_SERVERS_FILE, 'r') as f:
            valid_ips = set(line.split(':')[0] for line in f.readlines())
    except Exception as e:
        print(f"Failed to read {VALID_SERVERS_FILE}: {e}")
    
    remaining_ips = []
    
    for entry in ip_list:
        ip_sublist = []
        if '/' in entry:
            network = ip_network(entry, strict=False)
            ips = list(network.hosts())
            ips = [str(ip) for ip in ips if str(ip) not in valid_ips]
            if ips:
                print(f"Scanning CIDR block {entry} which contains {len(ips)} IP addresses.")
                all_ips.extend(ips)
                ip_sublist.extend(ips)
                total_ips += len(ips)
                remaining_ips.append(entry)
            else:
                print(f"\033[93mSkipping CIDR block {entry} (already scanned or contains valid servers).\033[0m")
        elif '-' in entry:
            start_ip, end_ip = entry.split('-')
            ips = ip_range_to_list(start_ip, end_ip)
            ips = [ip for ip in ips if ip not in valid_ips]
            if ips:
                all_ips.extend(ips)
                ip_sublist.extend(ips)
                total_ips += len(ips)
                remaining_ips.append(entry)
            else:
                print(f"\033[93mSkipping IP range {entry} (already scanned or contains valid servers).\033[0m")
        else:
            if entry not in valid_ips:
                all_ips.append(entry)
                ip_sublist.append(entry)
                total_ips += 1
                remaining_ips.append(entry)
                print(f"Scanning single IP address {entry}.")
            else:
                print(f"\033[93mSkipping single IP address {entry} (already scanned or valid server).\033[0m")
        
        if ip_sublist:
            with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                future_to_ip = {executor.submit(scan_ip, ip): ip for ip in ip_sublist}
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        future.result()
                    except Exception as exc:
                        print(f'{ip} generated an exception: {exc}')
            
            if not any_valid_ips_in_range(ip_sublist):
                print(f"\033[91mNo valid servers found in IP range {entry}. Removing from list.\033[0m")
                update_ips_file(entry)
            else:
                remaining_ips.append(entry)

def any_valid_ips_in_range(ip_sublist):
    valid_ips = set()
    try:
        with open(VALID_SERVERS_FILE, 'r') as f:
            valid_ips = set(line.split(':')[0] for line in f.readlines())
    except Exception as e:
        print(f"Failed to read {VALID_SERVERS_FILE}: {e}")
    
    for ip in ip_sublist:
        if ip in valid_ips:
            return True
    return False

def update_ips_file(entry_to_remove):
    try:
        with open('ips.txt', 'r') as f:
            entries = f.readlines()
        with open('ips.txt', 'w') as f:
            for entry in entries:
                if entry.strip() != entry_to_remove:
                    f.write(entry)
        print(f"Updated ips.txt by removing {entry_to_remove}.")
    except Exception as e:
        print(f"Failed to update ips.txt: {e}")

def sort_ips_by_size(filename):
    try:
        with open(filename, 'r') as file:
            ip_ranges = file.readlines()
        
        def get_range_size(entry):
            entry = entry.strip()
            if '/' in entry:
                network = ip_network(entry, strict=False)
                return network.num_addresses
            elif '-' in entry:
                start_ip, end_ip = entry.split('-')
                return int(ip_address(end_ip)) - int(ip_address(start_ip)) + 1
            else:
                return 1
        
        sorted_ip_ranges = sorted(ip_ranges, key=get_range_size)
        
        with open(filename, 'w') as file:
            file.writelines(sorted_ip_ranges)
        print(f"Sorted {filename} by IP range size.")
    except Exception as e:
        print(f"Failed to sort {filename}: {e}")

if __name__ == "__main__":
    remove_duplicates('ips.txt')
    remove_duplicates('validservers.txt')
    sort_ips_by_size('ips.txt')

    with open('ips.txt', 'r') as f:
        ip_list = [line.strip() for line in f.readlines()]
    
    print("Starting IP scan...")
    scan_ips(ip_list)
    print("IP scan completed.")

    try:
        with open(VALID_SERVERS_FILE, 'r') as f:
            valid_servers = len(f.readlines())
        print(f"\nTotal valid servers found: {valid_servers}")
    except Exception as e:
        print(f"Failed to read file: {e}")
