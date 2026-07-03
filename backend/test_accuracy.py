import sys
from processor import process_netflow_data
from metrics import calculate_accuracy_with_ground_truth, print_accuracy_report

def main():
    if len(sys.argv) < 2:
        print("Usage: python test_accuracy.py <ground_truth_file.csv>")
        sys.exit(1)
        
    gt_file = sys.argv[1]
    print(f"Testing against ground truth: {gt_file}")
    
    stats, alerts, charts = process_netflow_data(gt_file)
    accuracy_metrics = calculate_accuracy_with_ground_truth(gt_file, stats, alerts)
    print_accuracy_report(accuracy_metrics)
    
    precision = accuracy_metrics.get('precision', 0)
    recall = accuracy_metrics.get('recall', 0)
    f1 = accuracy_metrics.get('f1_score', 0)
    
    failed = False
    if precision < 0.75:
        print(f"ERROR: Precision {precision:.2%} is less than 75%")
        failed = True
    if recall < 0.60:
        print(f"ERROR: Recall {recall:.2%} is less than 60%")
        failed = True
    if f1 < 0.65:
        print(f"ERROR: F1-Score {f1:.2%} is less than 65%")
        failed = True
        
    if failed:
        sys.exit(1)
    
    print("Accuracy gate passed successfully.")
    sys.exit(0)

if __name__ == "__main__":
    main()
