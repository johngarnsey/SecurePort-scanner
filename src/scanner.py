import socket

def tcp_port_scan(target, ports):
    """
    Scans the specified ports on the target to check if they are open.

    Parameters:
    target (str): The IP address or hostname of the target device.
    ports (iterable): A list or range of ports to scan.
    """
    print(f"Starting scan on target: {target}")
    
    for port in ports:
        try:
            # Create a socket for each port to avoid conflicts
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)  # Set timeout to prevent long delays
                result = s.connect_ex((target, port))  # Attempt to connect
                if result == 0:
                    print(f"Port {port}: OPEN")  # Port is open
                else:
                    print(f"Port {port}: CLOSED")  # Port is closed or filtered
        except KeyboardInterrupt:
            print("\nScan interrupted by user. Exiting.")
            break
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
            continue

if __name__ == "__main__":
    print("SecurePort Scanner - Scan your home network securely.")
    
    # Prompt user for the target IP or hostname
    target = input("Enter the target IP address or hostname: ")
    
    # Define the range of ports to scan (1-1024 are commonly used for home networks)
    # This can be expanded to 65535 for a full scan if needed.
    ports = range(1, 1025)  # Scanning well-known and registered ports
    
    #
