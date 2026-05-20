import psutil
import time

def monitor_network_connections():
    print("--- Python Firewall Monitor & IDS Active ---")
    print("Monitoring active connections... Press Ctrl+C to stop.\n")
    
    seen_connections = set()

    try:
        while True:
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr:
                    ip, port = conn.raddr
                    conn_id = f"{ip}:{port}"
                    
                    if conn_id not in seen_connections:
                        seen_connections.add(conn_id)
                        
                        # Պարզ IDS վարքագիծ. HTTP (պորտ 80) տրաֆիկի հայտնաբերում
                        if port == 80:
                            print(f"[ALERT] ALERT: Unencrypted HTTP Traffic detected on port 80! -> To Destination: {ip}")
                        else:
                            print(f"[INFO] New Connection: Status={conn.status} -> Destination={ip}:{port} (PID={conn.pid})")
            
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[+] Monitoring stopped by user.")

if __name__ == "__main__":
    monitor_network_connections()
