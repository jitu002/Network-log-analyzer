import re
import csv
from collections import Counter

def log_file_analyzer(file_path, threshold=10):
    try:
        # Regular expression pattern searching    
        ip_address = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')  # IP Address IPv4
        end_point = re.compile(r'\"(?:GET|POST|PUT|DELETE|UPDATE) (\S+) HTTP')  # HTTP endpoints
        failed_login_attempts = re.compile(r'(401|Invalid credentials)')  # Failed login attempts

        ip_addresses = []
        end_points = []
        failed_logins = {}
        suspicious_ips = []
        flag=False

        # Opening files in python in read mode
        with open(file_path, "r") as log_file: 
            for line in log_file:
                ip_matches = ip_address.findall(line)  # Finding all IP addresses
                ip_addresses.extend(ip_matches)

                end_point_matches = end_point.findall(line)  # Finding all endpoints
                end_points.extend(end_point_matches)

                # Finding failed login attempts
                if failed_login_attempts.search(line):
                    for ip in ip_matches:
                        failed_logins[ip] = failed_logins.get(ip, 0) + 1

        # Check for suspicious activity
        for ip, count in failed_logins.items():
            if count >= threshold:
                suspicious_ips.append((ip, count))
                flag=True

        # Making a dictionary out of the list for better analysis 
        ip_counts = Counter(ip_addresses)
        end_point_counts = Counter(end_points)

        # Sorting in descending order to find the most affected easily
        sorted_ip = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        sorted_end_point = sorted(end_point_counts.items(), key=lambda x: x[1], reverse=True)
        sorted_failed_logins = sorted(failed_logins.items(), key=lambda x: x[1], reverse=True)

        # Writing in CSV file
        with open('log_analysis_results.csv', 'w', newline='') as csv_file:
            writer = csv.writer(csv_file)
            
            # Writing Requests per IP
            writer.writerow(['Network Details'])
            writer.writerow(['IP Address', 'Request Count'])
            writer.writerows(sorted_ip)
            writer.writerow(["-"*30, "-"*30])
            
            # Writing Most Accessed End Point
            writer.writerow(['Most Accessed End Point', 'No. of Accesses'])
            writer.writerow(sorted_end_point[0])
            writer.writerow(["-"*30, "-"*30])
            
            # Writing Failed Logins
            writer.writerow(["Failed Login Attempts:"])
            writer.writerow(["IP Address", "Failed Logins"])
            writer.writerows(sorted_failed_logins)
            
            # Writing Suspicious IPs
            writer.writerow(["-"*30, "-"*30])
            writer.writerow(["Suspicious Activity (Threshold: {} failed attempts):".format(threshold),("Detected" if flag else "Not Detected")])
            writer.writerow(["IP Address", "Failed Login Count"])
            writer.writerows(suspicious_ips)
        
        print("\nResults saved to 'log_analysis_results.csv'.")
    
    
    # Exception handling
    except FileNotFoundError:
        print("File not found")
    except Exception as e:
        print("Error occurred:", e)

# Function calling with required file-path as parameter
log_file_analyzer("./sample.log")