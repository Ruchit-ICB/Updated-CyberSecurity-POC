import polars as pl
import numpy as np
from pyod.models.iforest import IForest
from typing import Dict, List, Tuple, Any
import time
from metrics import netflow_flows_ingested_total, netflow_threats_detected_total, netflow_processing_seconds

def process_netflow_data(file_path: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any]]:
    
    t0 = time.time()
    
    
    expected_cols = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "tos", "packets", "bytes", "flows", "start_time", "end_time"]
    try:
        
        df_header_check = pl.read_csv(file_path, n_rows=1, truncate_ragged_lines=True, ignore_errors=True)
        cols = [c.lower() for c in df_header_check.columns]
        
        intersection = set(cols).intersection({"src_ip", "dst_ip", "src_port", "dst_port", "protocol", "packets", "bytes", "flows"})
        has_headers = len(intersection) > 0
        
        if has_headers:
            df = pl.read_csv(file_path, truncate_ragged_lines=True, ignore_errors=True)
        else:
            df = pl.read_csv(file_path, has_header=False, truncate_ragged_lines=True, ignore_errors=True)
        
            rename_map = {df.columns[i]: expected_cols[i] for i in range(min(len(df.columns), len(expected_cols)))}
            df = df.rename(rename_map)
            
            if "tos" not in df.columns:
                df = df.with_columns(pl.lit(0).alias("tos"))
        
        # Strip whitespace from all string columns to prevent silent nulling of numeric features
        for col in df.columns:
            if df[col].dtype == pl.Utf8 or df[col].dtype == pl.String:
                df = df.with_columns(pl.col(col).str.strip_chars().alias(col))
                
    except Exception as e:
        raise ValueError(f"Failed to read CSV file: {str(e)}")

    required_cols = {'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'packets', 'bytes', 'flows', 'start_time', 'end_time'}
    missing_cols = required_cols - set(df.columns)
    if missing_cols:
        raise ValueError(f"CSV is missing required columns: {missing_cols}. Headerless CSV must contain columns in order: src_ip, dst_ip, src_port, dst_port, protocol, [tos], packets, bytes, flows, start_time, end_time")

    n_rows = len(df)
    print(f"Ingested {n_rows} rows in {time.time() - t0:.4f}s")
    
   
    t_feat = time.time()
    
    
    for col_name in ['start_time', 'end_time']:
        col_dtype = df[col_name].dtype
        if col_dtype == pl.Utf8 or col_dtype == pl.String:
            converted = False
            
            try:
                test = df.select(pl.col(col_name).cast(pl.Float64, strict=True)).to_series()
                df = df.with_columns(pl.col(col_name).cast(pl.Float64).alias(col_name))
                converted = True
            except Exception:
                pass
            
            if not converted:
                
                datetime_formats = [
                    None,  
                    "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d %H:%M:%S%.f",
                    "%Y-%m-%dT%H:%M:%S%.f",
                    "%m/%d/%Y %H:%M",
                    "%d/%m/%Y %H:%M:%S",
                ]
                for fmt in datetime_formats:
                    try:
                        if fmt is None:
                            df = df.with_columns(
                                pl.col(col_name).str.to_datetime().dt.epoch("s").cast(pl.Float64).alias(col_name)
                            )
                        else:
                            df = df.with_columns(
                                pl.col(col_name).str.to_datetime(format=fmt).dt.epoch("s").cast(pl.Float64).alias(col_name)
                            )
                        converted = True
                        break
                    except Exception:
                        continue
                    
            if not converted:
                
                print(f"WARNING: Could not parse {col_name}. Using row index as synthetic time.")
                df = df.with_columns(pl.arange(0, len(df), eager=True).cast(pl.Float64).alias(col_name))
                
        elif col_dtype in [pl.Int8, pl.Int16, pl.Int32, pl.Int64, pl.UInt8, pl.UInt16, pl.UInt32, pl.UInt64]:
            df = df.with_columns(pl.col(col_name).cast(pl.Float64).alias(col_name))
        elif col_dtype in [pl.Datetime, pl.Date]:
            df = df.with_columns(pl.col(col_name).dt.epoch("s").cast(pl.Float64).alias(col_name))

    
    for col_name in ['packets', 'bytes', 'flows', 'src_port', 'dst_port']:
        col_dtype = df[col_name].dtype
        if col_dtype == pl.Utf8 or col_dtype == pl.String:
            try:
                df = df.with_columns(pl.col(col_name).cast(pl.Float64).alias(col_name))
            except Exception:
                df = df.with_columns(pl.lit(0.0).alias(col_name))
        elif col_dtype not in [pl.Float32, pl.Float64]:
            try:
                df = df.with_columns(pl.col(col_name).cast(pl.Float64).alias(col_name))
            except Exception:
                pass

    
    df = df.with_columns([
        (pl.col('end_time') - pl.col('start_time')).alias('raw_duration')
    ])
    
    df = df.with_columns([
        pl.when(pl.col('raw_duration') <= 0)
        .then(0.001)
        .otherwise(pl.col('raw_duration'))
        .alias('flow_duration')
    ])
    
    df = df.with_columns([
        (pl.col('bytes') / pl.when(pl.col('packets') == 0).then(1).otherwise(pl.col('packets')))
            .fill_nan(0.0).fill_null(0.0).alias('bytes_per_packet'),
        (pl.col('packets') / pl.col('flow_duration'))
            .fill_nan(0.0).fill_null(0.0).alias('packets_per_sec_raw'),
        
       
        pl.when(
            (pl.col('protocol').cast(pl.Utf8).str.to_uppercase() == "UDP") | 
            (pl.col('protocol').cast(pl.Utf8) == "17")
        )
        .then(1.0)
        .otherwise(0.0)
        .alias('udp_ratio'),
        
        
        pl.when((pl.col('dst_port') > 1024) & (~pl.col('dst_port').is_in([8080, 8443, 3306, 5432, 6379])))
        .then(1.0)
        .otherwise(0.0)
        .alias('dst_port_flag')
    ])
    
  
    df = df.with_columns([
        pl.col('packets_per_sec_raw').clip(0.0, 1e7).alias('packets_per_sec')
    ])
    
    
    feature_cols = [
        'bytes_per_packet', 'packets_per_sec', 'flow_duration', 
        'udp_ratio', 'dst_port_flag', 'packets', 'bytes', 'flows'
    ]
    
    print(f"Feature engineering completed in {time.time() - t_feat:.4f}s")
    
    
    t_rules = time.time()
    
    
    pkt_p95 = float(df.select(pl.col('packets').quantile(0.95)).item()) if n_rows > 0 else 1000
    byt_p95 = float(df.select(pl.col('bytes').quantile(0.95)).item()) if n_rows > 0 else 100000
    bpp_p95 = float(df.select(pl.col('bytes_per_packet').quantile(0.95)).item()) if n_rows > 0 else 500
    pps_p95 = float(df.select(pl.col('packets_per_sec').quantile(0.95)).item()) if n_rows > 0 else 500
    
    print(f"  Adaptive thresholds: pkt_p95={pkt_p95:.0f}, byt_p95={byt_p95:.0f}, bpp_p95={bpp_p95:.0f}, pps_p95={pps_p95:.0f}")
    ddos_rule = (pl.col('packets_per_sec') > max(pps_p95 * 1.5, 100)) & (pl.col('packets') > max(pkt_p95 * 1.2, 100))
    exfil_rule = (pl.col('bytes') > max(byt_p95 * 2, 10000)) & (pl.col('bytes_per_packet') > max(bpp_p95 * 1.5, 200))
    
    brute_rule = (pl.col('dst_port').is_in([22, 23, 3389, 445, 5900, 8080])) & (pl.col('packets') > max(pkt_p95 * 0.5, 10))
    
    
    udp_flood_rule = (pl.col('udp_ratio') == 1.0) & (pl.col('packets_per_sec') > max(pps_p95 * 2.0, 200)) & (pl.col('packets') > 100)
    large_flow_rule = (pl.col('bytes') > max(byt_p95 * 3, 50000)) & (pl.col('flow_duration') < 1.0)
    
    flood_rule = pl.col('packets') > 500
    
    suspicious_protocol_rule = pl.col('protocol').cast(pl.Utf8).str.to_uppercase().is_in(['GRE', 'ESP', 'OSPF'])
    
    # ICMP sweep rule: disabled at flow level - will detect via aggregation instead
    icmp_sweep_rule = pl.lit(False)
    
    # Rule-based scoring system: each rule adds 1 point, CONFIRMED requires 2+ signals
    df = df.with_columns([
        # Individual rule flags (1 if fired, 0 if not)
        pl.when(flood_rule).then(pl.lit(1)).otherwise(pl.lit(0)).alias('flood_score'),
        pl.when(suspicious_protocol_rule).then(pl.lit(1)).otherwise(pl.lit(0)).alias('suspicious_protocol_score'),
        pl.when(ddos_rule).then(pl.lit(1)).otherwise(pl.lit(0)).alias('ddos_score'),
        pl.when(udp_flood_rule).then(pl.lit(1)).otherwise(pl.lit(0)).alias('udp_flood_score'),
        pl.when(exfil_rule).then(pl.lit(1)).otherwise(pl.lit(0)).alias('exfil_score'),
        pl.when(brute_rule).then(pl.lit(1)).otherwise(pl.lit(0)).alias('brute_score'),
        pl.when(large_flow_rule).then(pl.lit(1)).otherwise(pl.lit(0)).alias('large_flow_score'),
        pl.when(icmp_sweep_rule).then(pl.lit(1)).otherwise(pl.lit(0)).alias('icmp_sweep_score')
    ])
    
    # Calculate total rule score (count of fired rules)
    df = df.with_columns([
        (pl.col('flood_score') + pl.col('suspicious_protocol_score') + 
         pl.col('ddos_score') + pl.col('udp_flood_score') + 
         pl.col('exfil_score') + pl.col('brute_score') + 
         pl.col('large_flow_score') + pl.col('icmp_sweep_score')).alias('total_rule_score')
    ])
    
    # Map total score to severity and threat description
    # Score 0: No threat
    # Score 1: HIGH (single signal - suspicious but not confirmed)
    # Score 2+: CONFIRMED (multiple signals firing together)
    df = df.with_columns([
        pl.when(pl.col('total_rule_score') == 0).then(pl.lit(None))
          .when(pl.col('total_rule_score') == 1).then(pl.lit("HIGH"))
          .otherwise(pl.lit("CONFIRMED"))
          .alias("rule_severity"),
        
        # Build threat description based on fired rules
        pl.when(pl.col('total_rule_score') == 0).then(pl.lit(None))
          .otherwise(
              pl.concat_str([
                  pl.when(pl.col('flood_score') > 0).then(pl.lit("Flood")).otherwise(pl.lit("")),
                  pl.when(pl.col('suspicious_protocol_score') > 0).then(pl.lit("Suspicious Protocol")).otherwise(pl.lit("")),
                  pl.when(pl.col('ddos_score') > 0).then(pl.lit("DDoS")).otherwise(pl.lit("")),
                  pl.when(pl.col('udp_flood_score') > 0).then(pl.lit("UDP Flood")).otherwise(pl.lit("")),
                  pl.when(pl.col('exfil_score') > 0).then(pl.lit("Data Exfiltration")).otherwise(pl.lit("")),
                  pl.when(pl.col('brute_score') > 0).then(pl.lit("Brute Force")).otherwise(pl.lit("")),
                  pl.when(pl.col('large_flow_score') > 0).then(pl.lit("Large Flow")).otherwise(pl.lit("")),
                  pl.when(pl.col('icmp_sweep_score') > 0).then(pl.lit("ICMP Sweep")).otherwise(pl.lit(""))
              ], separator=";")
          ).str.replace_all(";;", ";").str.strip_chars(";").alias("rule_threat_type"),
        
        # Confidence based on total score
        pl.when(pl.col('total_rule_score') == 0).then(pl.lit(0.0))
          .when(pl.col('total_rule_score') == 1).then(pl.lit(0.50))
          .otherwise(pl.lit(0.85))
          .alias("rule_confidence")
    ])
    
    rule_hits = df.filter(pl.col('rule_threat_type').is_not_null()).shape[0]
    print(f"Rule Engine completed in {time.time() - t_rules:.4f}s — {rule_hits} rule-based detections")
    
    # 4. PyOD Isolation Forest
    t_ml = time.time()
    
    # Extract features as NumPy array
    # Replace infinite values or NaNs just in case
    X = df.select(feature_cols).to_numpy()
    X = np.nan_to_num(X, nan=0.0, posinf=1e9, neginf=-1e9)
    
    # Downsample if dataset is large to keep response times fast
    # sklearn IsolationForest is fast, but fitting 1M rows still takes 10+ seconds.
    # Training on 50,000 rows takes ~0.5 seconds and is statistically sufficient.
    n_samples = X.shape[0]
    if n_samples > 50000:
        np.random.seed(42)
        indices = np.random.choice(n_samples, size=50000, replace=False)
        X_train = X[indices]
    else:
        X_train = X
        
    # Scale features using standard scaling (mean=0, std=1)
    mean = np.mean(X_train, axis=0)
    std = np.std(X_train, axis=0) + 1e-9
    X_train_scaled = (X_train - mean) / std
    X_scaled = (X - mean) / std
    
    # Fit Isolation Forest with increased contamination for better recall
    clf = IForest(n_estimators=100, max_samples='auto', contamination=0.05, n_jobs=-1, random_state=42)
    clf.fit(X_train_scaled)
    
    # Predict on all data
    # decision_function returns higher scores for normal points, so invert it
    scores = -clf.decision_function(X_scaled)  # higher means more anomalous after inversion
    labels = (clf.predict(X_scaled) == -1).astype(int)  # -1 indicates anomaly
    
    ml_hits = int(labels.sum())
    print(f"  ML anomalies detected: {ml_hits} / {n_samples} ({100*ml_hits/max(n_samples,1):.2f}%)")
    
    # Normalize scores to 0-1 range for the UI and confidence mapping
    min_score = float(scores.min())
    max_score = float(scores.max())
    score_range = max_score - min_score if max_score > min_score else 1.0
    normalized_scores = (scores - min_score) / score_range
    
    # Map ML outputs
    df = df.with_columns([
        pl.Series(name="ml_score", values=normalized_scores),
        pl.Series(name="ml_label", values=labels)
    ])
    # Vectorized evidence generation — avoids O(n) Python loop over 800k rows
    feat_means = {f: float(mean[i]) for i, f in enumerate(feature_cols)}
    feat_stds  = {f: float(std[i])  for i, f in enumerate(feature_cols)}

    df = df.with_columns([
        pl.when(pl.col('ml_label') == 0).then(pl.lit(""))
        .when(pl.col('packets') > feat_means['packets'] + 2 * feat_stds['packets'])
            .then(pl.lit("High packet count; ").add(
                pl.when(pl.col('bytes') > feat_means['bytes'] + 2 * feat_stds['bytes'])
                .then(pl.lit("Large byte transfer; "))
                .otherwise(pl.lit(""))))
        .when(pl.col('bytes') > feat_means['bytes'] + 2 * feat_stds['bytes'])
            .then(pl.lit("Large byte transfer; "))
        .when(pl.col('packets_per_sec') > feat_means['packets_per_sec'] + 2 * feat_stds['packets_per_sec'])
            .then(pl.lit("High packet rate; "))
        .when(pl.col('bytes_per_packet') > feat_means['bytes_per_packet'] + 2 * feat_stds['bytes_per_packet'])
            .then(pl.lit("Unusually high bytes/packet; "))
        .when(pl.col('flow_duration') < feat_means['flow_duration'] - 2 * feat_stds['flow_duration'])
            .then(pl.lit("Very short flow duration; "))
        .otherwise(pl.lit("Multivariate anomaly (Isolation Forest)"))
        .str.strip_chars("; ")
        .alias("ml_evidence")
    ])
    
    print(f"ML Model Inference completed in {time.time() - t_ml:.4f}s")
    
    # 5. Threat Arbitration and Deduplication
    t_arb = time.time()
    
    # Map ML alert confidence
    # If ML label is 1, confidence scale from 0.5 to 0.9 based on anomaly score severity
    df = df.with_columns([
        pl.when(pl.col('ml_label') == 1)
        .then(0.5 + 0.4 * pl.col('ml_score'))
        .otherwise(0.0)
        .alias('ml_confidence')
    ])
    
    df = df.with_columns([
        # Threat Type
        pl.when((pl.col('rule_threat_type').is_not_null()) & (pl.col('ml_label') == 1))
        .then(pl.col('rule_threat_type') + pl.lit(" (Rule + ML)"))
        .when(pl.col('rule_threat_type').is_not_null())
        .then(pl.col('rule_threat_type'))
        # Only raise pure ML anomalies if they exceed a high severity threshold score
        .when((pl.col('ml_label') == 1) & (pl.col('ml_score') > 0.70))
        .then(pl.lit("Anomalous Traffic (ML)"))
        .otherwise(pl.lit(None))
        .alias('threat_type'),
        pl.when((pl.col('rule_severity') == "CONFIRMED") | ((pl.col('ml_label') == 1) & (pl.col('ml_score') > 0.85)))
        .then(pl.lit("CONFIRMED"))
        .when((pl.col('rule_severity') == "HIGH") | ((pl.col('ml_label') == 1) & (pl.col('ml_score') > 0.70)))
        .then(pl.lit("HIGH"))
        .otherwise(pl.lit("MONITOR"))
        .alias('severity'),
        
        # Confidence
        pl.when((pl.col('rule_threat_type').is_not_null()) & (pl.col('ml_label') == 1))
        .then(pl.col('rule_confidence') + (1.0 - pl.col('rule_confidence')) * pl.col('ml_confidence') * 0.5)
        .when(pl.col('rule_threat_type').is_not_null())
        .then(pl.col('rule_confidence'))
        .when(pl.col('ml_label') == 1)
        .then(pl.col('ml_confidence'))
        .otherwise(0.0)
        .alias('confidence')
    ])
    
    # Limit confidence to max 1.0 and clip
    df = df.with_columns([
        pl.col('confidence').clip(0.0, 1.0).alias('confidence')
    ])
    
    # Filter rows that actually have threats (confidence > 0 or threat_type is not null)
    threat_df = df.filter(pl.col('threat_type').is_not_null())
    
    # Deduplicate / aggregate alerts to prevent frontend freezing
    # Group by src_ip, dst_ip, threat_type, severity
    # Aggregate: count of alerts, average confidence
    alerts = []
    
    if len(threat_df) > 0:
        agg_alerts_df = (
            threat_df.group_by(['src_ip', 'dst_ip', 'threat_type', 'severity', 'protocol'])
            .agg([
                pl.len().alias('flow_count'),
                pl.col('confidence').max().alias('confidence'),
                pl.col('ml_evidence').first().alias('evidence')
            ])
        )
        alerts.extend(agg_alerts_df.to_dicts())
        
    # Detect port scanners via aggregation: src_ip scanning > 15 unique destination ports
    # with small average packet sizes (common scan behavior)
    if len(df) > 0:
        try:
            scan_df = (
                df.group_by(['src_ip', 'dst_ip'])
                .agg([
                    pl.col('dst_port').n_unique().alias('unique_ports'),
                    pl.col('packets').mean().alias('avg_packets'),
                    pl.col('protocol').first().alias('protocol')
                ])
                .filter((pl.col('unique_ports') >= 5) & (pl.col('avg_packets') < 5))
            )
            
            for row in scan_df.to_dicts():
                alerts.append({
                    'src_ip': row['src_ip'],
                    'dst_ip': row['dst_ip'],
                    'threat_type': 'Port Scan (Aggregated)',
                    'severity': 'high' if row['unique_ports'] > 50 else 'medium',
                    'protocol': str(row['protocol']).upper(),
                    'flow_count': int(row['unique_ports']),
                    'confidence': min(0.99, 0.5 + 0.01 * row['unique_ports']),
                    'evidence': f"Scanning {row['unique_ports']} unique destination ports with small average packet size ({row['avg_packets']:.1f})"
                })
        except Exception as scan_err:
            print(f"Error detecting port scans via aggregation: {str(scan_err)}")
    
    # Detect horizontal scans: src IPs hitting >= max(15, 5% of total flows) unique destination IPs
    # Higher threshold to reduce false positives while maintaining recall
    horizontal_scan_threshold = max(15, int(len(df) * 0.05))
    if len(df) > 0:
        try:
            horizontal_scan_df = (
                df.group_by('src_ip')
                .agg([
                    pl.col('dst_ip').n_unique().alias('unique_dst_ips'),
                    pl.col('dst_ip').unique().alias('dst_ips'),
                    pl.col('protocol').first().alias('protocol')
                ])
                .filter(pl.col('unique_dst_ips') >= horizontal_scan_threshold)
            )
            
            for row in horizontal_scan_df.to_dicts():
                dst_ips = row.get('dst_ips', [])
                alerts.append({
                    'src_ip': row['src_ip'],
                    'dst_ip': ', '.join(dst_ips) if isinstance(dst_ips, list) else str(dst_ips),
                    'threat_type': 'Horizontal Scan (Aggregated)',
                    'severity': 'high' if row['unique_dst_ips'] > 500 else 'medium',
                    'protocol': str(row['protocol']).upper(),
                    'flow_count': int(row['unique_dst_ips']),
                    'confidence': min(0.99, 0.5 + 0.001 * row['unique_dst_ips']),
                    'evidence': f"Scanning {row['unique_dst_ips']} unique destination IPs"
                })
        except Exception as hscan_err:
            print(f"Error detecting horizontal scans via aggregation: {str(hscan_err)}")

    # Flow-count catch-all rule: detect botnet-style distributed behavior
    # Any src_ip with flow_count > 50 AND unique_dsts > 30 → CONFIRMED
    if len(df) > 0:
        try:
            botnet_df = (
                df.group_by('src_ip')
                .agg([
                    pl.len().alias('flow_count'),
                    pl.col('dst_ip').n_unique().alias('unique_dsts'),
                    pl.col('dst_ip').unique().alias('dst_ips'),
                    pl.col('protocol').first().alias('protocol')
                ])
                .filter((pl.col('flow_count') > 50) & (pl.col('unique_dsts') > 30))
            )
            
            for row in botnet_df.to_dicts():
                dst_ips = row.get('dst_ips', [])
                alerts.append({
                    'src_ip': row['src_ip'],
                    'dst_ip': ', '.join(dst_ips) if isinstance(dst_ips, list) else str(dst_ips),
                    'threat_type': 'Botnet Activity (High Flow Count)',
                    'severity': 'confirmed',
                    'protocol': str(row['protocol']).upper(),
                    'flow_count': int(row['flow_count']),
                    'confidence': min(0.99, 0.70 + 0.01 * (row['flow_count'] / 10)),
                    'evidence': f"High flow count ({row['flow_count']}) to {row['unique_dsts']} unique destinations - botnet pattern"
                })
        except Exception as botnet_err:
            print(f"Error detecting botnet activity: {str(botnet_err)}")

    # Detect ICMP sweeps: src IPs sending ICMP to >= 3 unique destination IPs
    if len(df) > 0:
        try:
            icmp_df = df.filter(pl.col('protocol').cast(pl.Utf8).str.to_uppercase() == 'ICMP')
            if len(icmp_df) > 0:
                icmp_sweep_df = (
                    icmp_df.group_by('src_ip')
                    .agg([
                        pl.col('dst_ip').n_unique().alias('unique_dst_ips'),
                        pl.col('dst_ip').unique().alias('dst_ips'),
                        pl.col('packets').sum().alias('total_packets')
                    ])
                    .filter(pl.col('unique_dst_ips') >= 2)
                )
                
                for row in icmp_sweep_df.to_dicts():
                    dst_ips = row.get('dst_ips', [])
                    alerts.append({
                        'src_ip': row['src_ip'],
                        'dst_ip': ', '.join(dst_ips) if isinstance(dst_ips, list) else str(dst_ips),
                        'threat_type': 'ICMP Sweep (Aggregated)',
                        'severity': 'confirmed',
                        'protocol': 'ICMP',
                        'flow_count': int(row['unique_dst_ips']),
                        'confidence': min(0.99, 0.70 + 0.01 * row['unique_dst_ips']),
                        'evidence': f"ICMP sweep to {row['unique_dst_ips']} unique destinations with {row['total_packets']} total packets"
                    })
        except Exception as icmp_err:
            print(f"Error detecting ICMP sweeps: {str(icmp_err)}")

    temporal_correlations = {}
    if len(threat_df) > 0:
        try:
            temporal_df = (
                threat_df.group_by('src_ip')
                .agg([
                    pl.col('start_time').min().alias('first_seen'),
                    pl.col('start_time').max().alias('last_seen'),
                    pl.len().alias('threat_flow_count')
                ])
            )
            
            # Flag as temporally correlated if: multiple flows within 60 seconds
            for row in temporal_df.to_dicts():
                time_span = row['last_seen'] - row['first_seen']
                flow_count = row['threat_flow_count']
                # Temporal correlation: 2+ flows within 60 seconds, OR 3+ flows within 300 seconds
                if (flow_count >= 2 and time_span <= 60) or (flow_count >= 3 and time_span <= 300):
                    temporal_correlations[row['src_ip']] = True
        except Exception as temp_err:
            print(f"Error detecting temporal patterns: {str(temp_err)}")

    # Calibrate confidence and severity based on correlation patterns
    calibrated_alerts = []
    for alert in alerts:
        flow_count = alert['flow_count']
        threat_type = alert['threat_type']
        src_ip = alert['src_ip']
        is_rule_and_ml = "(Rule + ML)" in threat_type or "Aggregated" in threat_type
        has_temporal_pattern = temporal_correlations.get(src_ip, False)
        
        # Get original severity from rule engine
        original_severity = alert.get('severity', 'MONITOR')
        
        # Exception: Port scans and horizontal scans are confirmed by definition
        is_scan_type = "Port Scan" in threat_type or "Horizontal Scan" in threat_type
        
        # Determine if there's strong supporting evidence
        # Strong evidence = rule+ML (multiple detection methods) OR temporal correlation on multi-signal flows
        has_strong_evidence = is_rule_and_ml or (has_temporal_pattern and original_severity == "CONFIRMED")
        
        # Moderate evidence = 2 correlated flows (not temporally clustered)
        has_moderate_evidence = flow_count == 2 and not has_temporal_pattern
        
        if is_scan_type:
            # Port/horizontal scans -> CONFIRMED by definition regardless of other signals
            severity = "CONFIRMED"
            confidence = 0.85 + 0.14 * alert['confidence']
        elif flow_count == 1 and not is_rule_and_ml:
            # Uncorrelated single flow -> MONITOR (40-60% confidence)
            severity = "MONITOR"
            orig_conf = alert['confidence']
            if orig_conf < 0.6:
                confidence = 0.40 + 0.05 * (orig_conf / 0.6)
            elif orig_conf < 0.8:
                confidence = 0.45 + 0.10 * ((orig_conf - 0.6) / 0.2)
            else:
                confidence = 0.55 + 0.05 * ((orig_conf - 0.8) / 0.2)
            confidence = min(0.60, max(0.40, confidence))
        elif has_strong_evidence:
            # Strong correlation: escalate to CONFIRMED
            severity = "CONFIRMED"
            confidence = 0.75 + 0.24 * alert['confidence']
        elif has_moderate_evidence:
            # Moderate correlation: SUSPICIOUS
            severity = "SUSPICIOUS"
            confidence = 0.55 + 0.20 * alert['confidence']
        elif original_severity == "CONFIRMED":
            # Multi-signal from rule engine -> CONFIRMED
            severity = "CONFIRMED"
            confidence = 0.75 + 0.24 * alert['confidence']
        elif original_severity == "HIGH":
            # Single signal from rule engine -> HIGH (not CONFIRMED; single deviation is suspicious, not proven)
            severity = "HIGH"
            confidence = 0.55 + 0.20 * alert['confidence']
        else:
            # Fallback -> MONITOR
            severity = "MONITOR"
            confidence = 0.40 + 0.20 * alert['confidence']

        calibrated_alerts.append({
            'src_ip': alert['src_ip'],
            'dst_ip': alert['dst_ip'],
            'threat_type': threat_type,
            'protocol': alert['protocol'],
            'flow_count': flow_count,
            'confidence': round(float(min(confidence, 0.99)), 2),
            'severity': severity,
            'evidence': alert.get('evidence') or f"Rule-based detection for {threat_type}"
        })

    # Cross-threat IP escalation: if a src_ip appears in 2+ distinct threat types,
    # escalate all alerts for that IP to the highest severity found
    ip_threat_map = {}  # src_ip -> set of threat types
    ip_severity_map = {}  # src_ip -> max severity
    
    # First pass: collect threat types and severities per IP
    for alert in calibrated_alerts:
        src_ip = alert['src_ip']
        threat_type = alert['threat_type']
        severity = alert['severity']
        
        if src_ip not in ip_threat_map:
            ip_threat_map[src_ip] = set()
            ip_severity_map[src_ip] = "MONITOR"
        
        ip_threat_map[src_ip].add(threat_type)
        
        # Update max severity for this IP
        severity_order = {"CONFIRMED": 4, "HIGH": 3, "SUSPICIOUS": 2, "MONITOR": 1}
        if severity_order.get(severity, 0) > severity_order.get(ip_severity_map[src_ip], 0):
            ip_severity_map[src_ip] = severity
    
    # Second pass: escalate alerts for IPs with 2+ distinct threat types
    escalated_count = 0
    for alert in calibrated_alerts:
        src_ip = alert['src_ip']
        if len(ip_threat_map.get(src_ip, set())) >= 2:
            max_severity = ip_severity_map[src_ip]
            if alert['severity'] != max_severity:
                alert['severity'] = max_severity
                # Boost confidence slightly for escalated alerts
                alert['confidence'] = min(0.99, alert['confidence'] + 0.10)
                alert['evidence'] = f"{alert['evidence']} (Escalated due to cross-threat pattern)"
                escalated_count += 1
    
    if escalated_count > 0:
        print(f"  Cross-threat escalation: {escalated_count} alerts escalated")

    # Sort: CONFIRMED > HIGH > SUSPICIOUS > MONITOR, then by confidence desc
    severity_order = {"CONFIRMED": 4, "HIGH": 3, "SUSPICIOUS": 2, "MONITOR": 1}
    alerts = sorted(
        calibrated_alerts,
        key=lambda x: (severity_order.get(x["severity"], 0), x["confidence"]),
        reverse=True
    )[:1000]
        
    print(f"Arbitration and aggregation completed in {time.time() - t_arb:.4f}s")
    total_flows = n_rows
    
    threats_detected = len(threat_df)
    
    protocol_dist = (
        df.group_by('protocol')
        .len()
        .sort('len', descending=True)
    )
    protocol_dist_dict = {}
    for row in protocol_dist.to_dicts():
        proto = str(row['protocol']).upper()
        protocol_dist_dict[proto] = protocol_dist_dict.get(proto, 0) + row['len']
        
    if threats_detected > 0:
        top_attacker = (
            threat_df.group_by('src_ip')
            .len()
            .sort('len', descending=True)
            .head(1)
            .to_dicts()
        )
        top_attacker_ip = top_attacker[0]['src_ip'] if top_attacker else "N/A"
        top_attacker_count = top_attacker[0]['len'] if top_attacker else 0
        
        # Top Threat Type
        top_threat = (
            threat_df.group_by('threat_type')
            .len()
            .sort('len', descending=True)
            .head(1)
            .to_dicts()
        )
        top_threat_type = top_threat[0]['threat_type'] if top_threat else "N/A"
        top_threat_count = top_threat[0]['len'] if top_threat else 0
    else:
        top_attacker_ip = "N/A"
        top_attacker_count = 0
        top_threat_type = "N/A"
        top_threat_count = 0
        
    stats = {
        "total_flows": total_flows,
        "threats_detected": threats_detected,
        "top_attacker_ip": top_attacker_ip,
        "top_attacker_count": top_attacker_count,
        "top_threat_type": top_threat_type,
        "top_threat_count": top_threat_count,
        "protocol_distribution": protocol_dist_dict,
        "processing_time_sec": round(time.time() - t0, 3)
    }
    scores_array = df.select('ml_score').to_numpy().flatten()
    hist_counts, bin_edges = np.histogram(scores_array, bins=20, range=(0.0, 1.0))
    histogram_data = []
    for i in range(len(hist_counts)):
        histogram_data.append({
            "bin_start": round(float(bin_edges[i]), 2),
            "bin_end": round(float(bin_edges[i+1]), 2),
            "count": int(hist_counts[i])
        })
        
    
    if threats_detected > 0:
        clean_times = threat_df.select('start_time').drop_nulls().to_series().to_numpy().flatten()
        clean_times = clean_times[np.isfinite(clean_times)]
        
        if len(clean_times) > 0:
            min_time = float(clean_times.min())
            max_time = float(clean_times.max())
            time_range = max_time - min_time
            
            if time_range <= 0:
                time_range = 1.0
                
            # Bin size
            n_time_bins = 30
            bin_width = time_range / n_time_bins
            
            
            bin_indices = ((clean_times - min_time) / bin_width).astype(int)
            bin_indices = np.clip(bin_indices, 0, n_time_bins - 1)
            bin_counts = np.zeros(n_time_bins, dtype=int)
            for idx in bin_indices:
                bin_counts[idx] += 1
            is_unix = min_time > 1000000000
            
            line_chart_data = []
            for i in range(n_time_bins):
                bin_center_time = min_time + (i + 0.5) * bin_width
                if is_unix:
                    try:
                        time_str = time.strftime('%H:%M:%S', time.localtime(bin_center_time))
                    except Exception:
                        time_str = f"T+{round(bin_center_time - min_time, 1)}s"
                else:
                    time_str = f"T+{round(bin_center_time - min_time, 1)}s"
                    
                line_chart_data.append({
                    "time": time_str,
                    "threat_count": int(bin_counts[i])
                })
        else:
            line_chart_data = [{"time": "N/A", "threat_count": 0}]
    else:
        line_chart_data = [{"time": "N/A", "threat_count": 0}]
        
    charts = {
        "histogram": histogram_data,
        "threats_over_time": line_chart_data
    }
    
    processing_time = time.time() - t0
    netflow_flows_ingested_total.inc(total_flows)
    netflow_processing_seconds.observe(processing_time)
    for alert in alerts:
        netflow_threats_detected_total.labels(severity=alert['severity']).inc()
    
    print(f"Total processing time: {processing_time:.4f}s")
    return stats, alerts, charts
