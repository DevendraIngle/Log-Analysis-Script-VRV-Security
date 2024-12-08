import re
import csv
from collections import Counter, defaultdict

# Define a threshold for suspicious activity detection
SUSPICIOUS_THRESHOLD = 10

# File paths
LOG_FILE_PATH = 'sample.log'
RESULTS_FILE_PATH = 'log_analysis_report.csv'


def process_log_file(file_path):
    """Process the log file and extract relevant data like IP addresses, endpoints, and failed attempts."""
    with open(file_path, 'r') as file:
        log_lines = file.readlines()

    ip_request_counts = Counter()
    endpoint_requests = Counter()
    failed_login_counts = defaultdict(int)

    for log in log_lines:
        # Extracting IP address
        ip_match = re.search(r'^([\d.]+)', log)
        ip = ip_match.group(1) if ip_match else None

        # Extracting the endpoint and status code
        endpoint_match = re.search(r'\"[A-Z]+\s(\/[\w\/]*)\s', log)
        endpoint = endpoint_match.group(1) if endpoint_match else None
        status_code_match = re.search(r'\s(\d{3})\s', log)
        status_code = int(status_code_match.group(1)) if status_code_match else None

        # Counting requests by IP
        if ip:
            ip_request_counts[ip] += 1

        # Counting requests by endpoint
        if endpoint:
            endpoint_requests[endpoint] += 1

        # Track failed login attempts
        if status_code == 401:
            failed_login_counts[ip] += 1

    return ip_request_counts, endpoint_requests, failed_login_counts


def generate_analysis_report(ip_request_counts, endpoint_requests, failed_login_counts):
    """Generates a summary report by analyzing the extracted data."""
    # Sort IP addresses based on request frequency
    sorted_ip_list = sorted(ip_request_counts.items(), key=lambda x: x[1], reverse=True)

    # Identify the most frequently accessed endpoint
    most_frequented_endpoint = max(endpoint_requests.items(), key=lambda x: x[1])

    # Identify suspicious IPs based on failed login attempts
    flagged_ips = {ip: count for ip, count in failed_login_counts.items() if count > SUSPICIOUS_THRESHOLD}

    return sorted_ip_list, most_frequented_endpoint, flagged_ips


def export_to_csv(sorted_ip_list, most_frequented_endpoint, flagged_ips, output_file):
    """Exports the analysis results to a CSV file."""
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Writing IP requests to CSV
        writer.writerow(['IP Address', 'Request Count'])
        writer.writerows(sorted_ip_list)

        # Writing the most accessed endpoint to CSV
        writer.writerow([])
        writer.writerow(['Most Frequently Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_frequented_endpoint[0], most_frequented_endpoint[1]])

        # Writing suspicious activity to CSV
        writer.writerow([])
        writer.writerow(['Suspicious Activity Detected'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        writer.writerows(flagged_ips.items())


def main():
    print("Starting log analysis...")

    # Step 1: Parse the log file
    ip_request_counts, endpoint_requests, failed_login_counts = process_log_file(LOG_FILE_PATH)

    # Step 2: Analyze the results
    sorted_ip_list, most_frequented_endpoint, flagged_ips = generate_analysis_report(ip_request_counts, endpoint_requests, failed_login_counts)

    # Step 3: Display the results
    print("\nIP Address             Request Count")
    for ip, count in sorted_ip_list:
        print(f"{ip:<20} {count}")

    print(f"\nMost Frequently Accessed Endpoint:\n{most_frequented_endpoint[0]} (Accessed {most_frequented_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in flagged_ips.items():
        print(f"{ip:<20} {count}")

    # Step 4: Save results to CSV
    export_to_csv(sorted_ip_list, most_frequented_endpoint, flagged_ips, RESULTS_FILE_PATH)
    print(f"\nResults saved to {RESULTS_FILE_PATH}")


if __name__ == "__main__":
    main()
