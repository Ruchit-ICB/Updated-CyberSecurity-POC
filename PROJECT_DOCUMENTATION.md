# NetFlow Threat Detection System - Complete Documentation

## Project Overview

This is a cybersecurity threat detection system that analyzes NetFlow data to identify malicious network activities. The system uses a hybrid approach combining rule-based detection with machine learning (Isolation Forest) to detect anomalies like DDoS attacks, data exfiltration, port scanning, and brute force attempts.

### Key Features

- **Hybrid Detection Engine**: Combines rule-based heuristics with ML anomaly detection
- **Calibrated Scoring**: Single uncorrelated flows are labeled as MONITOR (40-60% confidence), while SUSPICIOUS/CONFIRMED require supporting evidence
- **Evidence Generation**: Each ML anomaly includes human-readable explanations of why it was flagged
- **Temporal Pattern Detection**: Identifies correlated attacks occurring in time clusters
- **Real-time Processing**: Optimized for large datasets (handles 1M+ rows efficiently)
- **Interactive Dashboard**: React-based frontend for visualization and analysis

---

## Architecture

### Backend (FastAPI + Python)
- **Framework**: FastAPI with Uvicorn server
- **Data Processing**: Polars for high-performance data manipulation
- **ML Model**: PyOD Isolation Forest for anomaly detection
- **Rule Engine**: Custom Polars-based rule evaluation

### Frontend (React + Vite)
- **Framework**: React 19 with Vite
- **Charts**: Recharts for data visualization
- **Icons**: Lucide React

---

## Project Structure

```
Updated cybersecurity poc/
├── backend/
│   ├── processor.py          # Core data processing and threat detection logic
│   ├── main.py               # FastAPI server and API endpoints
│   ├── generate_mock_data.py # Script to generate test NetFlow data
│   ├── test_processor.py     # Test script for processor
│   ├── requirements.txt       # Python dependencies
│   ├── mock_netflow_10k.csv  # Test data (10K rows)
│   ├── mock_netflow_1m.csv   # Test data (1M rows)
│   └── venv/                 # Python virtual environment
├── frontend/
│   ├── src/
│   │   ├── App.jsx           # Main React application
│   │   └── ...               # Other React components
│   ├── package.json          # Node.js dependencies
│   └── vite.config.js        # Vite configuration
└── PROJECT_DOCUMENTATION.md  # This file
```

---

## Installation & Setup

### Prerequisites
- Python 3.8+
- Node.js 16+
- npm

### Backend Setup

```bash
cd backend
python -m venv venv
venv\Scripts\activate  # On Windows
pip install -r requirements.txt
```

### Frontend Setup

```bash
cd frontend
npm install
```

---

## Running the Application

### Start Backend

```bash
cd backend
python main.py
```

Backend runs on: `http://0.0.0.0:8000`

### Start Frontend

```bash
cd frontend
npm run dev
```

Frontend runs on: `http://localhost:5173` (or next available port)

---

## API Endpoints

### POST /upload
Upload a NetFlow CSV file for analysis.

**Request**: multipart/form-data with file
**Response**: 
```json
{
  "status": "success",
  "message": "File processed successfully",
  "processing_time_sec": 1.684,
  "total_flows": 10000,
  "threats_detected": 139
}
```

### GET /alerts
Retrieve processed alerts with optional filtering.

**Query Parameters**:
- `severity`: Filter by severity (high, medium, low, MONITOR, SUSPICIOUS, CONFIRMED)
- `protocol`: Filter by protocol (TCP, UDP, ICMP, etc.)

**Response**: Array of alert objects
```json
[
  {
    "src_ip": "192.168.1.50",
    "dst_ip": "10.0.0.118",
    "threat_type": "DDoS Attack (Rule + ML)",
    "protocol": "TCP",
    "flow_count": 1,
    "confidence": 0.98,
    "severity": "CONFIRMED",
    "evidence": "High packet rate (35120 packets/sec vs baseline 565); High packet count (68049 vs baseline 711)"
  }
]
```

### GET /stats
Retrieve summary statistics and chart data.

**Response**:
```json
{
  "stats": {
    "total_flows": 10000,
    "threats_detected": 139,
    "top_attacker_ip": "192.168.1.50",
    "top_attacker_count": 11,
    "top_threat_type": "UDP Flood",
    "top_threat_count": 82,
    "protocol_distribution": {"TCP": 7048, "UDP": 2436, "ICMP": 516},
    "processing_time_sec": 1.684
  },
  "charts": {
    "histogram": [...],
    "threats_over_time": [...]
  }
}
```

---

## CSV File Format

### Expected Columns
- `src_ip`: Source IP address
- `dst_ip`: Destination IP address
- `src_port`: Source port number
- `dst_port`: Destination port number
- `protocol`: Protocol (TCP, UDP, ICMP, etc.)
- `tos`: Type of Service (optional, defaults to 0 if missing)
- `packets`: Number of packets
- `bytes`: Number of bytes
- `flows`: Number of flows
- `start_time`: Start time (epoch seconds or datetime string)
- `end_time`: End time (epoch seconds or datetime string)

### Notes
- CSV can have headers or be headerless
- Headerless CSV must have columns in the exact order listed above
- Time columns support multiple formats: epoch seconds, ISO datetime, etc.

---

## Threat Detection Logic

### Rule-Based Detection

The system uses adaptive percentile-based thresholds computed dynamically from the data:

| Threat Type | Rule | Severity | Base Confidence |
|-------------|------|----------|-----------------|
| DDoS Attack | High packet rate AND high packet count | high | 0.95 |
| UDP Flood | UDP traffic with very high packet rate | high | 0.90 |
| Data Exfiltration | Very large byte transfer AND large bytes per packet | high | 0.92 |
| Brute Force | Suspicious ports with above-average packet counts | medium | 0.80 |
| Suspicious Large Flow | Abnormally large flows with short duration | medium | 0.70 |

**Adaptive Thresholds**:
- `pkt_p95`: 95th percentile of packet counts
- `byt_p95`: 95th percentile of byte counts
- `bpp_p95`: 95th percentile of bytes per packet
- `pps_p95`: 95th percentile of packets per second

### ML Anomaly Detection

**Model**: PyOD Isolation Forest
- `n_estimators`: 100
- `max_samples`: 512
- `contamination`: 0.005 (0.5% expected anomalies)
- `n_jobs`: -1 (parallel processing)

**Features Used**:
- bytes_per_packet
- packets_per_sec
- flow_duration
- udp_ratio
- dst_port_flag
- packets
- bytes
- flows

---

## Calibration Logic

The system implements a sophisticated calibration system to reduce false positives:

### Severity Levels

**MONITOR** (40-60% confidence)
- Single uncorrelated flows without rule-based detection
- Low confidence to avoid alert fatigue
- Requires manual review if pattern persists

**SUSPICIOUS** (55-75% confidence)
- 2 correlated flows without temporal clustering
- Moderate evidence requiring investigation

**CONFIRMED** (75-99% confidence)
- Rule + ML combined detection
- Temporal correlation (2+ flows within 60s, or 3+ within 300s)
- 3+ correlated flows
- Strong evidence requiring immediate action

### Temporal Pattern Detection

The system detects temporal correlations by analyzing:
- Time span between flows from the same source IP
- Flow count within time windows
- Flags as temporally correlated if:
  - 2+ flows within 60 seconds, OR
  - 3+ flows within 300 seconds

This identifies burst attacks like DDoS or scanning that happen in clusters.

---

## Evidence Generation

Each ML anomaly includes human-readable evidence explaining why it was flagged:

### Evidence Types

**Feature Deviation Evidence** (z-score > 2.0):
- "Unusually high bytes per packet (1566 vs baseline 525)"
- "High packet rate (35120 packets/sec vs baseline 565)"
- "Long flow duration (47.3s vs baseline 5.1s)"
- "Large byte transfer (55000000 bytes vs baseline 332166)"
- "Traffic to privileged system ports"
- "Unusual UDP traffic pattern"

**Aggregated Evidence**:
- "Scanning 15 unique destination ports with small average packet size (5.2)"

**Multivariate Evidence**:
- "Multivariate anomaly detected by Isolation Forest" (when no single feature deviation is significant)

### Evidence Calculation

For each anomaly, the system:
1. Computes z-scores for all 8 features
2. Flags features with |z-score| > 2.0
3. Generates human-readable comparisons to baseline (mean)
4. Combines all reasons into a semicolon-separated string

---

## Alert Aggregation & Deduplication

To prevent frontend overload with thousands of individual alerts:

1. **Group by**: src_ip, dst_ip, threat_type, severity, protocol
2. **Aggregate**:
   - `flow_count`: Number of flows in the group
   - `confidence`: Maximum confidence in the group
   - `evidence`: First evidence string
3. **Limit**: Return top 1000 alerts sorted by severity and confidence

### Port Scan Detection

Additional aggregation detects port scanners:
- Groups by src_ip, dst_ip
- Counts unique destination ports
- Flags if 15+ unique ports with small average packet size (< 10)
- Severity: high if > 50 ports, medium otherwise

---

## Performance Characteristics

### Processing Speed
- 10K rows: ~0.4 seconds
- 1M rows: ~6 seconds
- Scales linearly with dataset size

### Optimization Techniques
- Polars for fast data manipulation
- ML model downsampling (50K samples for training)
- Parallel processing (n_jobs=-1)
- Efficient feature engineering with vectorized operations

---

## Testing

### Run Processor Tests

```bash
cd backend
python test_processor.py
```

This tests with both `mock_netflow_10k.csv` and `mock_netflow_1m.csv`.

### Generate Mock Data

```bash
cd backend
python generate_mock_data.py
```

Generates realistic NetFlow data with embedded threats for testing.

---

## Dependencies

### Backend (requirements.txt)
```
fastapi
uvicorn
polars
numpy
pyod
pandas
```

### Frontend (package.json)
```
react
react-dom
lucide-react
recharts
vite
```

---

## Configuration

### Backend Configuration

**Upload Directory**:
- Windows: `C:\Temp\netflow_uploads`
- Unix/Linux: `/tmp/netflow_uploads`

**ML Model Parameters** (in processor.py):
- `n_estimators`: 100
- `max_samples`: 512
- `contamination`: 0.005
- `random_state`: 42

**Rule Thresholds** (adaptive, computed per dataset):
- DDoS: packets_per_sec > max(pps_p95 * 1.5, 100) AND packets > max(pkt_p95 * 1.2, 100)
- Exfil: bytes > max(byt_p95 * 2, 10000) AND bytes_per_packet > max(bpp_p95 * 1.5, 200)
- Brute Force: dst_port in [22, 23, 3389, 445, 5900, 8080] AND packets > max(pkt_p95 * 0.5, 10)
- UDP Flood: udp_ratio == 1.0 AND packets_per_sec > max(pps_p95 * 1.2, 80)
- Large Flow: bytes > max(byt_p95 * 3, 50000) AND flow_duration < 1.0

---

## Troubleshooting

### Common Issues

**CSV Parsing Error**: `could not parse '3.3' as dtype 'i64'`
- Cause: Decimal value in integer column or duplicate column names
- Solution: Clean CSV file, ensure ports are integers, remove duplicate headers

**No Alerts Generated**
- Check if thresholds are too high for your data
- Verify CSV has required columns
- Try with mock data files first

**Frontend Cannot Connect to Backend**
- Ensure backend is running on port 8000
- Check CORS settings in main.py
- Verify firewall settings

---

## Future Enhancements

Potential improvements for the system:

1. **Historical Baselines**: Store historical data to compute long-term baselines
2. **Whitelist/Blacklist**: Add IP whitelist and blacklist functionality
3. **Real-time Streaming**: Support for real-time NetFlow stream processing
4. **Alert Export**: Export alerts to CSV, JSON, or SIEM systems
5. **Custom Rules**: Allow users to define custom detection rules
6. **ML Model Retraining**: Periodic model retraining with new data
7. **Geolocation**: Add IP geolocation for threat context
8. **User Authentication**: Add authentication and authorization
9. **Alert Notifications**: Email/SMS/Webhook notifications for high-severity alerts

---

## License & Credits

This is a proof-of-concept cybersecurity threat detection system demonstrating hybrid rule-based and ML approaches for NetFlow analysis.

---

## Contact & Support

For issues or questions about this project, please refer to the code comments or contact the development team.
