import time
import os
from processor import process_netflow_data

def run_test(filename: str):
    if not os.path.exists(filename):
        print(f"File {filename} does not exist. Please generate it first.")
        return
        
    print(f"\n--- Testing processor with {filename} ---")
    t0 = time.time()
    try:
        stats, alerts, charts = process_netflow_data(filename)
        print(f"Status: Success!")
        print(f"Total processing time: {time.time() - t0:.3f}s")
        print(f"Stats returned: {stats}")
        print(f"Number of alerts: {len(alerts)}")
        
        # Verify calibration: count by severity
        severity_counts = {"MONITOR": 0, "SUSPICIOUS": 0, "CONFIRMED": 0}
        for alert in alerts:
            sev = alert.get("severity", "UNKNOWN")
            if sev in severity_counts:
                severity_counts[sev] += 1
        print(f"Severity distribution: {severity_counts}")
        
        # Check confidence ranges for MONITOR alerts
        monitor_confidences = [a["confidence"] for a in alerts if a.get("severity") == "MONITOR"]
        if monitor_confidences:
            print(f"MONITOR confidence range: {min(monitor_confidences):.2f} - {max(monitor_confidences):.2f}")
        
        if alerts:
            print(f"Sample alert: {alerts[0]}")
            # Show evidence for a few alerts
            print(f"Sample evidences:")
            for i, alert in enumerate(alerts[:3]):
                print(f"  {i+1}. {alert.get('threat_type', 'N/A')}: {alert.get('evidence', 'N/A')}")
        print(f"Histogram bins: {len(charts['histogram'])}")
        print(f"Timeline points: {len(charts['threats_over_time'])}")
    except Exception as e:
        print(f"Error during processing: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Test with 10k rows first
    run_test("mock_netflow_10k.csv")
    # Test with 1m rows if generated
    run_test("mock_netflow_1m.csv")
