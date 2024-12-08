import pandas as pd
import re
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Function to parse the log file and extract relevant data
def parse_log(log_file):
    """
    Parses the log file and extracts relevant data such as IP addresses, 
    HTTP methods, requested URLs, status codes, response sizes, and user agents.
    
    Args:
    log_file (str): Path to the log file to be parsed.
    
    Returns:
    pd.DataFrame: A pandas DataFrame containing parsed log data.
    """
    log_data = []
    
    # Regular expression pattern to match the log file structure
    log_pattern = r'(?P<ip_address>\S+) - - \[.*\] "(?P<method>\S+) (?P<requested_url>\S+) \S+" (?P<status_code>\d+) (?P<size>\d+) "(?P<user_agent>.*?)"'
    
    # Open and read the log file line by line
    with open(log_file, 'r') as file:
        for line in file:
            match = re.match(log_pattern, line)
            if match:
                # Add each matched line's data to the list
                log_data.append(match.groupdict())
    
    # Convert the collected data into a pandas DataFrame for easy analysis
    df = pd.DataFrame(log_data)
    return df

# Function to analyze the log data and generate insights
def analyze_log_data(df):
    """
    Analyzes the parsed log data to generate insights such as the total number of 
    requests, top 5 IP addresses, top 5 requested URLs, and the most frequently 
    accessed endpoint.
    
    Args:
    df (pd.DataFrame): The parsed log data as a DataFrame.
    
    Returns:
    tuple: A tuple containing total requests, top 5 IPs, top 5 requested URLs,
           most accessed URL, and its count.
    """
    # Check if the DataFrame is empty
    if df.empty:
        print("No data to analyze.")
        return None, None, None, None, None

    # Calculate total number of requests
    total_requests = len(df)

    # Get the top 5 IP addresses based on the number of requests
    top_ips = df['ip_address'].value_counts().head(5)

    # Get the top 5 requested URLs
    top_urls = df['requested_url'].value_counts().head(5)

    # Find the most frequently accessed URL and its count
    most_accessed_url = df['requested_url'].value_counts().idxmax()
    most_accessed_count = df['requested_url'].value_counts().max()

    return total_requests, top_ips, top_urls, most_accessed_url, most_accessed_count

# Function to generate a PDF report with the analyzed data
def generate_pdf_report(total_requests, top_ips, top_urls, most_accessed_url, most_accessed_count):
    """
    Generates a PDF report containing the log analysis results.
    
    Args:
    total_requests (int): Total number of requests in the log.
    top_ips (pd.Series): Top 5 IP addresses based on request counts.
    top_urls (pd.Series): Top 5 requested URLs based on request counts.
    most_accessed_url (str): The most frequently accessed URL.
    most_accessed_count (int): The count of the most accessed URL.
    """
    # Create a new PDF file to store the report
    report_file = "log_analysis_report.pdf"
    c = canvas.Canvas(report_file, pagesize=letter)
    
    # Title of the report
    c.setFont("Helvetica", 12)
    c.drawString(100, 750, "Log File Analysis Report")
    
    # Add the total number of requests to the report
    c.drawString(100, 730, f"Total Requests: {total_requests}")
    
    # Add the top 5 IP addresses and their request counts
    c.drawString(100, 710, "Top 5 IP Addresses:")
    y_position = 690
    for ip, count in top_ips.items():
        c.drawString(100, y_position, f"{ip}: {count} requests")
        y_position -= 20
    
    # Add the most frequently accessed URL and its request count
    c.drawString(100, y_position - 10, "Most Frequently Accessed Endpoint:")
    c.drawString(100, y_position - 30, f"{most_accessed_url}: {most_accessed_count} requests")
    y_position -= 50
    
    # Add the top 5 requested URLs and their counts
    c.drawString(100, y_position - 10, "Top 5 Requested URLs:")
    y_position -= 30
    for url, count in top_urls.items():
        c.drawString(100, y_position, f"{url}: {count} requests")
        y_position -= 20
    
    # Save the PDF
    c.save()
    print(f"Report saved as {report_file}")

# Main Script to execute the log analysis process
def main():
    log_file = "sample.log"  # Specify the path to the log file here

    # Step 1: Parse the log file and get the data as a DataFrame
    df = parse_log(log_file)

    # Step 2: Analyze the parsed data to get insights
    total_requests, top_ips, top_urls, most_accessed_url, most_accessed_count = analyze_log_data(df)

    # Step 3: Generate and save the PDF report based on the analysis results
    generate_pdf_report(total_requests, top_ips, top_urls, most_accessed_url, most_accessed_count)

# Run the script if this is the main module
if __name__ == "__main__":
    main()
