import csv
import random
import time
import os

def generate_mock_netflow(filename: str, num_rows: int = 1000000):
    print(f"Generating {num_rows} rows of mock NetFlow data into {filename}...")
    t0 = time.time()
    
    # Common IPs
    ips = [f"192.168.1.{i}" for i in range(2, 254)]
    external_ips = [f"10.0.0.{i}" for i in range(2, 254)] + [f"8.8.8.{i}" for i in range(1, 10)] + [f"198.51.100.{i}" for i in range(1, 50)]
    
    protocols = ["TCP", "UDP", "ICMP"]
    
    # Open file for writing
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        # Header
        writer.writerow([
            "src_ip", "dst_ip", "src_port", "dst_port", 
            "protocol", "tos", "packets", "bytes", 
            "flows", "start_time", "end_time"
        ])
        
        base_time = 1719835200 # July 1, 2024
        
        for i in range(num_rows):
            # 99.5% normal traffic, 0.5% anomalies
            anomaly_type = None
            if i % 200 == 0:
                anomaly_type = random.choice(["ddos", "exfil", "brute", "udp_flood"])
                
            # Base variables
            src_port = random.randint(1024, 65535)
            tos = random.choice([0, 16, 32, 64])
            flows = 1
            
            # Start/End times
            # Let's spread start time over a 2-hour window
            start_time = base_time + random.randint(0, 7200)
            
            if anomaly_type == "ddos":
                # DDoS: High packets, very short duration -> high packets_per_sec
                src_ip = random.choice(external_ips)
                dst_ip = "192.168.1.10" # target
                dst_port = 80
                protocol = "TCP"
                packets = random.randint(60000, 100000)
                bytes_val = packets * random.randint(40, 60) # small packets
                duration = random.uniform(0.1, 2.0)
                end_time = start_time + duration
                
            elif anomaly_type == "exfil":
                # Exfiltration: Large bytes, high bytes_per_packet
                src_ip = "192.168.1.50" # source
                dst_ip = random.choice(external_ips) # exfil destination
                dst_port = 443
                protocol = "TCP"
                packets = random.randint(30000, 50000)
                bytes_val = packets * random.randint(1300, 1450) # large bytes per packet
                # We need bytes > 50,000,000 to trigger rule
                bytes_val = max(bytes_val, 55000000)
                duration = random.uniform(10, 60)
                end_time = start_time + duration
                
            elif anomaly_type == "brute":
                # Brute force: Port 22, 23, 3389, 445, packets > 2000
                src_ip = random.choice(external_ips)
                dst_ip = "192.168.1.100"
                dst_port = random.choice([22, 23, 3389, 445])
                protocol = "TCP"
                packets = random.randint(2500, 5000)
                bytes_val = packets * random.randint(60, 100)
                duration = random.uniform(5, 30)
                end_time = start_time + duration
                
            elif anomaly_type == "udp_flood":
                # UDP Flood: UDP, high packets_per_sec
                src_ip = random.choice(external_ips)
                dst_ip = "192.168.1.20"
                dst_port = random.randint(10000, 20000)
                protocol = "UDP"
                packets = random.randint(20000, 40000)
                bytes_val = packets * random.randint(40, 80)
                duration = random.uniform(0.1, 1.0)
                end_time = start_time + duration
                
            else:
                # Normal Traffic
                src_ip = random.choice(ips)
                dst_ip = random.choice(external_ips) if random.random() > 0.3 else random.choice(ips)
                # Ensure they are different
                while dst_ip == src_ip:
                    dst_ip = random.choice(ips)
                    
                dst_port = random.choice([80, 443, 53, 123, random.randint(1024, 65535)])
                protocol = random.choices(protocols, weights=[70, 25, 5], k=1)[0]
                
                # Normal metrics
                packets = random.randint(1, 1000)
                bytes_val = packets * random.randint(60, 1000)
                duration = random.uniform(0.1, 10.0)
                end_time = start_time + duration
                flows = random.randint(1, 3)

            writer.writerow([
                src_ip, dst_ip, src_port, dst_port,
                protocol, tos, packets, bytes_val,
                flows, round(start_time, 4), round(end_time, 4)
            ])
            
            # Print progress
            if (i + 1) % 250000 == 0:
                print(f"  Written {i+1} rows...")
                
    print(f"Finished generating {num_rows} rows in {time.time() - t0:.2f} seconds.")

if __name__ == "__main__":
    generate_mock_netflow("mock_netflow_1m.csv", 1000000)
    # Also generate a smaller 10k row version for rapid debugging
    generate_mock_netflow("mock_netflow_10k.csv", 10000)
