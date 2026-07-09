"""
Metrics calculation for threat detection system.
Analyzes detection results with and without ground truth labels.
"""

from typing import Dict, List, Any, Tuple
import polars as pl
from prometheus_client import Counter, Histogram, Gauge

netflow_flows_ingested_total = Counter('netflow_flows_ingested_total', 'Total number of netflow flows ingested')
netflow_threats_detected_total = Counter('netflow_threats_detected_total', 'Total number of threats detected', ['severity'])
netflow_processing_seconds = Histogram('netflow_processing_seconds', 'Time spent processing netflow data')
netflow_active_uploads = Gauge('netflow_active_uploads', 'Number of currently active file uploads')


def calculate_detection_metrics(stats: Dict[str, Any], alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculate detection metrics from stats and alerts.
    
    Args:
        stats: Statistics dictionary from process_netflow_data
        alerts: List of alert dictionaries
    
    Returns:
        Dictionary containing calculated metrics
    """
    total_flows = stats.get('total_flows', 0)
    threats_detected = stats.get('threats_detected', 0)
    num_alerts = len(alerts)
    
    # Detection rate: percentage of flows that triggered any rule
    detection_rate = (threats_detected / total_flows * 100) if total_flows > 0 else 0
    
    # Alert aggregation ratio: how many threats were consolidated into alerts
    aggregation_ratio = (threats_detected / num_alerts) if num_alerts > 0 else 0
    
    # Severity distribution
    severity_counts = {}
    confidence_by_severity = {}
    
    for alert in alerts:
        severity = alert.get('severity', 'UNKNOWN')
        confidence = alert.get('confidence', 0)
        
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        if severity not in confidence_by_severity:
            confidence_by_severity[severity] = []
        confidence_by_severity[severity].append(confidence)
    
    # Calculate average confidence per severity
    avg_confidence_by_severity = {}
    for severity, confidences in confidence_by_severity.items():
        avg_confidence_by_severity[severity] = sum(confidences) / len(confidences) if confidences else 0
    
    # Threat type distribution
    threat_type_counts = {}
    for alert in alerts:
        threat_type = alert.get('threat_type', 'UNKNOWN')
        threat_type_counts[threat_type] = threat_type_counts.get(threat_type, 0) + 1
    
    # Protocol distribution from stats
    protocol_dist = stats.get('protocol_distribution', {})
    
    return {
        'detection_rate_percent': round(detection_rate, 2),
        'threats_detected': threats_detected,
        'total_flows': total_flows,
        'num_alerts': num_alerts,
        'aggregation_ratio': round(aggregation_ratio, 2),
        'severity_distribution': severity_counts,
        'avg_confidence_by_severity': {k: round(v, 3) for k, v in avg_confidence_by_severity.items()},
        'threat_type_distribution': threat_type_counts,
        'protocol_distribution': protocol_dist,
        'processing_time_sec': stats.get('processing_time_sec', 0),
        'throughput_flows_per_sec': round(total_flows / stats.get('processing_time_sec', 1), 2) if stats.get('processing_time_sec', 0) > 0 else 0
    }


def print_metrics_report(metrics: Dict[str, Any]) -> None:
    """Print a formatted metrics report."""
    print("\n" + "="*60)
    print("THREAT DETECTION METRICS REPORT")
    print("="*60)
    
    print(f"\nDetection Performance:")
    print(f"  Total flows processed: {metrics['total_flows']:,}")
    print(f"  Threats detected: {metrics['threats_detected']:,} ({metrics['detection_rate_percent']}%)")
    print(f"  Alerts generated: {metrics['num_alerts']:,}")
    print(f"  Aggregation ratio: {metrics['aggregation_ratio']:.1f} threats per alert")
    
    print(f"\nProcessing Performance:")
    print(f"  Processing time: {metrics['processing_time_sec']:.3f}s")
    print(f"  Throughput: {metrics['throughput_flows_per_sec']:,.0f} flows/sec")
    
    print(f"\nSeverity Distribution:")
    for severity, count in metrics['severity_distribution'].items():
        percentage = (count / metrics['num_alerts'] * 100) if metrics['num_alerts'] > 0 else 0
        avg_conf = metrics['avg_confidence_by_severity'].get(severity, 0)
        print(f"  {severity}: {count} ({percentage:.1f}%) - avg confidence: {avg_conf:.3f}")
    
    print(f"\nTop Threat Types:")
    sorted_threats = sorted(metrics['threat_type_distribution'].items(), key=lambda x: x[1], reverse=True)
    for threat_type, count in sorted_threats[:5]:
        percentage = (count / metrics['num_alerts'] * 100) if metrics['num_alerts'] > 0 else 0
        print(f"  {threat_type}: {count} ({percentage:.1f}%)")
    
    print(f"\nProtocol Distribution:")
    for protocol, count in metrics['protocol_distribution'].items():
        print(f"  {protocol}: {count}")
    
    print("\n" + "="*60)


def calculate_accuracy_with_ground_truth(
    ground_truth_path: str,
    stats: Dict[str, Any],
    alerts: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Calculate accuracy metrics using ground truth labels.
    
    Args:
        ground_truth_path: Path to CSV file with 'label' column
        stats: Statistics dictionary from process_netflow_data
        alerts: List of alert dictionaries
    
    Returns:
        Dictionary containing accuracy metrics
    """
    # Read ground truth
    gt_df = pl.read_csv(ground_truth_path)
    
    # Parse labels: BENIGN vs THREAT/EDGE
    gt_df = gt_df.with_columns([
        pl.when(pl.col('label').str.contains('BENIGN'))
        .then(pl.lit('benign'))
        .otherwise(pl.lit('threat'))
        .alias('ground_truth')
    ])
    
    # Count ground truth
    total_gt = gt_df.shape[0]
    benign_count = gt_df.filter(pl.col('ground_truth') == 'benign').shape[0]
    threat_count = gt_df.filter(pl.col('ground_truth') == 'threat').shape[0]
    
    # Create a set of detected IPs from alerts (IP-level detection)
    detected_ips = set()
    for alert in alerts:
        src_ip = alert.get('src_ip')
        if src_ip:
            detected_ips.add(src_ip)
    
    # Get unique threat IPs and benign IPs from ground truth
    threat_ips = set(gt_df.filter(pl.col('ground_truth') == 'threat').select('src_ip').unique().to_series().to_list())
    benign_ips = set(gt_df.filter(pl.col('ground_truth') == 'benign').select('src_ip').unique().to_series().to_list())
    
    # Check each unique IP
    true_positives = 0
    false_positives = 0
    true_negatives = 0
    false_negatives = 0
    
    for ip in threat_ips:
        if ip in detected_ips:
            true_positives += 1
        else:
            false_negatives += 1
    
    for ip in benign_ips:
        if ip in detected_ips:
            false_positives += 1
        else:
            true_negatives += 1
    
    # Calculate metrics (IP-level)
    total_ips = len(threat_ips) + len(benign_ips)
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (true_positives + true_negatives) / total_ips if total_ips > 0 else 0
    false_positive_rate = false_positives / len(benign_ips) if len(benign_ips) > 0 else 0
    false_negative_rate = false_negatives / len(threat_ips) if len(threat_ips) > 0 else 0
    
    return {
        'total_ground_truth': total_gt,
        'benign_count': benign_count,
        'threat_count': threat_count,
        'unique_threat_ips': len(threat_ips),
        'unique_benign_ips': len(benign_ips),
        'true_positives': true_positives,
        'false_positives': false_positives,
        'true_negatives': true_negatives,
        'false_negatives': false_negatives,
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1_score': round(f1_score, 4),
        'accuracy': round(accuracy, 4),
        'false_positive_rate': round(false_positive_rate, 4),
        'false_negative_rate': round(false_negative_rate, 4)
    }


def print_accuracy_report(accuracy_metrics: Dict[str, Any]) -> None:
    """Print a formatted accuracy report."""
    print("\n" + "="*60)
    print("GROUND TRUTH ACCURACY REPORT (IP-Level)")
    print("="*60)
    
    print(f"\nGround Truth Distribution:")
    print(f"  Total flows: {accuracy_metrics['total_ground_truth']}")
    print(f"  Unique threat IPs: {accuracy_metrics['unique_threat_ips']}")
    print(f"  Unique benign IPs: {accuracy_metrics['unique_benign_ips']}")
    
    print(f"\nConfusion Matrix (IP-Level):")
    print(f"  True Positives (TP):  {accuracy_metrics['true_positives']}")
    print(f"  False Positives (FP): {accuracy_metrics['false_positives']}")
    print(f"  True Negatives (TN):  {accuracy_metrics['true_negatives']}")
    print(f"  False Negatives (FN): {accuracy_metrics['false_negatives']}")
    
    print(f"\nPerformance Metrics:")
    print(f"  Accuracy:  {accuracy_metrics['accuracy']:.2%}")
    print(f"  Precision: {accuracy_metrics['precision']:.2%}")
    print(f"  Recall:    {accuracy_metrics['recall']:.2%}")
    print(f"  F1-Score:  {accuracy_metrics['f1_score']:.2%}")
    print(f"  FPR:       {accuracy_metrics['false_positive_rate']:.2%}")
    print(f"  FNR:       {accuracy_metrics['false_negative_rate']:.2%}")
    
    print("\n" + "="*60)


if __name__ == "__main__":
    import sys
    
    # Check if ground truth file is provided
    if len(sys.argv) > 1:
        gt_file = sys.argv[1]
        print(f"Testing against ground truth: {gt_file}")
        
        from processor import process_netflow_data
        
        # Process the ground truth file
        stats, alerts, charts = process_netflow_data(gt_file)
        
        # Calculate accuracy
        accuracy_metrics = calculate_accuracy_with_ground_truth(gt_file, stats, alerts)
        print_accuracy_report(accuracy_metrics)
        
        # Also print general metrics
        metrics = calculate_detection_metrics(stats, alerts)
        print_metrics_report(metrics)
    else:
        print("Usage: python metrics.py <ground_truth_file.csv>")
        print("\nRunning mock data tests instead...")
        
        from processor import process_netflow_data
        
        # Test with 10K rows
        stats_10k, alerts_10k, charts_10k = process_netflow_data("mock_netflow_10k.csv")
        metrics_10k = calculate_detection_metrics(stats_10k, alerts_10k)
        print_metrics_report(metrics_10k)
