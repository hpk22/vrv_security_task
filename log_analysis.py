import os
import re
import sys
import csv
from typing import Dict, List, Tuple, Optional

class WebTrafficAnalyzer:
    
    def __init__(self, log_file_path: str, failed_login_threshold: int = 10):
        """
        Here I initialized parameters for log file analysis.

        :param log_file_path: Path to the web server log file
        :param failed_login_threshold: Threshold to flag suspicious login attempts
        """
        self.log_file_path = log_file_path
        self.failed_login_threshold = failed_login_threshold
        
        # defining dic for tracking  log insights
        self.ip_request_count: Dict[str, int] = {}
        self.resource_access_count: Dict[str, int] = {}
        self.failed_login_attempts: Dict[str, int] = {}

    def _parse_log_line(self, log_line: str) -> Optional[Tuple[str, str, int, bool]]:
        """
        Extract structured data from a log entry.

        :param log_line: Its a single line from the log file
        :return: A tuple containing (IP address, requested resource, status code, is_failed_login)
        """
        log_pattern = r'^(\d+\.\d+\.\d+\.\d+).*"(GET|POST) (/\S+).*" (\d+)(?:.*"(.*)")?'
        match = re.search(log_pattern, log_line)
        
        if match:
            ip_address = match.group(1)
            resource = match.group(3)
            status_code = int(match.group(4))
            error_message = match.group(5) if match.group(5) else ''
            
            #  It is a failed login attempt if:
            # 1. Resource is /login
            # 2. Status code is 401
            # 3. Contains "Invalid credentials" or similar
            is_failed_login = (
                '/login' in resource and 
                status_code == 401 and 
                ('Invalid credentials' in error_message or 'failed' in error_message.lower())
            )
            
            return (ip_address, resource, status_code, is_failed_login)
        return None

    def analyze_log_file(self) -> None:
        """
        Did processesing of log file and extract insights related to web traffic.
        """
        try:
            with open(self.log_file_path, 'r') as log_file:
                for line in log_file:
                    log_data = self._parse_log_line(line)
                    
                    if log_data:
                        ip_address, resource_path, status_code, is_failed_login = log_data
                        
                        self.ip_request_count[ip_address] = \
                            self.ip_request_count.get(ip_address, 0) + 1
                        
                        
                        self.resource_access_count[resource_path] = \
                            self.resource_access_count.get(resource_path, 0) + 1
                        
                    
                        if is_failed_login:
                            self.failed_login_attempts[ip_address] = \
                                self.failed_login_attempts.get(ip_address, 0) + 1
        
        except IOError as error:
            print(f"[ERROR] Unable to read the log file: {error}")
            sys.exit(1)

    def get_most_accessed_resource(self) -> Tuple[str, int]:
        """
        found the most frequently accessed resource from the log.
        """
        return max(
            self.resource_access_count.items(), 
            key=lambda item: item[1]
        )

    def detect_failed_logins(self) -> List[Tuple[str, int]]:
        """
        identifying IP addresses with suspicious login patterns.

        """
        return [
            (ip, attempts) 
            for ip, attempts in self.failed_login_attempts.items()
            if attempts > 0  # Captures failed login attempts
        ]

    def generate_analysis_report(self) -> None:
        """
        here I created a csv report summarizing the findings from log analysis.
        """
        sorted_requests = sorted(
            self.ip_request_count.items(), 
            key=lambda x: x[1], 
            reverse=True
        )

        with open('log_analysis_results.csv', 'w', newline='') as report_file:
            csv_writer = csv.writer(report_file)
            
            # Requests per IP Section
            csv_writer.writerow(['Requests per IP'])
            csv_writer.writerow(['IP Address', 'Request Count'])
            csv_writer.writerows(sorted_requests)
            
            csv_writer.writerow([])  # Separator
            
            # Most Accessed Resource Section
            top_resource, access_count = self.get_most_accessed_resource()
            csv_writer.writerow(['Most Accessed Endpoint:'])
            csv_writer.writerow([top_resource, access_count])
            
            csv_writer.writerow([])  # Separator
            
            # Suspicious Login Activity Section
            suspicious_ips = self.detect_failed_logins()
            csv_writer.writerow(['Suspicious Activity:'])
            csv_writer.writerow(['IP Address', 'Failed Login Count'])
            if suspicious_ips:
                csv_writer.writerows(suspicious_ips)
            else:
                csv_writer.writerow(['No suspicious activity detected'])

    def display_analysis_results(self) -> None:
       
        print("\n--- Web Traffic Analysis ---\n")
        
        # Display the top network sources by request count
        print("Requests per IP:")
        for ip, count in sorted(
            self.ip_request_count.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:5]:
            print(f"{ip:<15} {count:>4} requests")
        
        print("\nMost Accessed Resource:")
        top_resource, access_count = self.get_most_accessed_resource()
        print(f"{top_resource} (Accessed {access_count} times)")
        
        # Display any detected suspicious login attempts
        failed_logins = self.detect_failed_logins()
        if failed_logins:
            print("\nSuspicious Activity:")
            for ip, attempts in failed_logins:
                print(f"{ip:<15} {attempts:>4} failed login attempts")
        else:
            print("\nNo suspicious activity detected.")

    def run_analysis(self) -> None:
        """
        1. Display results in the terminal.
        2. Generate the report in csv format.
        """
        self.analyze_log_file()
        self.display_analysis_results()
        self.generate_analysis_report()

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = 'sample.log'
    
    web_traffic_analyzer = WebTrafficAnalyzer(log_file)
    web_traffic_analyzer.run_analysis()

if __name__ == '__main__':
    main()
