#!/usr/bin/env python3
import sqlite3
import argparse
import nmap
import logging
import socket
import concurrent.futures
import csv
import os
import requests
from datetime import datetime

# --- Configuration & Setup ---
# Disable SSL warnings for the web audit portion to prevent console clutter
requests.packages.urllib3.disable_warnings()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def parse_ports(port_arg):
    """
    Parses a string of ports (e.g., '80,443,1-10') into a sorted list of unique integers.
    
    Args:
        port_arg (str): String input from CLI.
    Returns:
        list: Sorted unique port integers.
    """
    ports = []
    for section in port_arg.split(','):
        if '-' in section:
            try:
                start, end = map(int, section.split('-'))
                ports.extend(range(start, end + 1))
            except ValueError:
                logger.error(f"Invalid range: {section}")
        else:
            try:
                ports.append(int(section))
            except ValueError:
                logger.error(f"Invalid port: {section}")
    return sorted(list(set(ports)))

# --- Database Management ---
class PortScannerDB:
    """
    Handles all SQLite persistence logic, including schema creation, 
    data migrations, and reporting queries.
    """
    def __init__(self, db_path='port_scan_results.db'):
        self.db_path = db_path
        self.init_database()
        self.migrate_database()

    def init_database(self):
        """Initializes tables for hosts, ports, and vulnerabilities, and creates reporting views."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        # Table for general host information
        cursor.execute('''CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ip_address TEXT, hostname TEXT, 
            status TEXT, scan_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        # Table for port-specific service details
        cursor.execute('''CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT, host_id INTEGER,
            port_number INTEGER, protocol TEXT, service_name TEXT,
            state TEXT, product TEXT, version TEXT,
            FOREIGN KEY (host_id) REFERENCES hosts (id))''')
        # Table for found vulnerabilities mapped to ports
        cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT, port_id INTEGER,
            vuln_id TEXT, severity TEXT, description TEXT, owasp_category TEXT,
            FOREIGN KEY (port_id) REFERENCES ports (id))''')
        
        # View to simplify complex HTML report generation
        cursor.execute('''CREATE VIEW IF NOT EXISTS view_vulnerability_report AS
            SELECT h.ip_address, h.hostname, h.scan_timestamp, p.port_number, p.service_name, 
                   v.vuln_id, v.severity, v.description, v.owasp_category
            FROM hosts h 
            JOIN ports p ON h.id = p.host_id
            LEFT JOIN vulnerabilities v ON p.id = v.port_id''')
        conn.commit()
        conn.close()

    def migrate_database(self):
        """Ensures the database schema is up to date (Self-healing)."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('ALTER TABLE vulnerabilities ADD COLUMN owasp_category TEXT;')
            conn.commit()
        except sqlite3.OperationalError:
            pass # Column already exists
        conn.close()

    def get_last_scan_ports(self, ip):
        """Fetches the ports found open in previous scans for delta analysis (new port detection)."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''SELECT p.port_number FROM ports p 
                          JOIN hosts h ON p.id = h.id 
                          WHERE h.ip_address = ? 
                          ORDER BY h.scan_timestamp DESC LIMIT 100''', (ip,))
        results = [row[0] for row in cursor.fetchall()]
        conn.close()
        return set(results)

    def save_results(self, scan_data):
        """Commits full scan results to the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        for ip, host_data in scan_data.items():
            cursor.execute('INSERT INTO hosts (ip_address, hostname, status) VALUES (?, ?, ?)',
                         (ip, host_data['hostname'], host_data['status']))
            host_id = cursor.lastrowid
            for p in host_data['ports']:
                cursor.execute('''INSERT INTO ports (host_id, port_number, protocol, service_name, state, product, version) 
                               VALUES (?, ?, ?, ?, ?, ?, ?)''', 
                               (host_id, p['port'], p['protocol'], p['service'], p['state'], p.get('product'), p.get('version')))
                port_id = cursor.lastrowid
                for v in p.get('vulnerabilities', []):
                    cursor.execute('''INSERT INTO vulnerabilities (port_id, vuln_id, description, severity, owasp_category)
                                   VALUES (?, ?, ?, ?, ?)''',
                                   (port_id, v['id'], v['output'], v.get('severity', 'Info'), v.get('owasp', 'N/A')))
        conn.commit()
        conn.close()

    def get_all_results_for_report(self):
        """Reconstructs the scan hierarchy (Host -> Port -> Vuln) for the HTML generator."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM hosts ORDER BY scan_timestamp DESC")
        hosts = [dict(row) for row in cursor.fetchall()]
        for host in hosts:
            cursor.execute("SELECT * FROM ports WHERE host_id = ?", (host['id'],))
            ports = [dict(row) for row in cursor.fetchall()]
            for port in ports:
                cursor.execute("SELECT * FROM vulnerabilities WHERE port_id = ?", (port['id'],))
                port['vulnerabilities'] = [dict(row) for row in cursor.fetchall()]
            host['ports'] = ports
        conn.close()
        return hosts

# --- Scanning Logic ---
class AdvancedPortScanner:
    """
    The core engine: Performs socket checks, Nmap service detection, 
    web auditing, and report generation.
    """
    def __init__(self, db_handler):
        self.db = db_handler
        self.nm = nmap.PortScanner()
        self.dynamic_timeout = 0.5
        self.csv_file = "tested_credentials.csv"
        self._init_csv()

    def _init_csv(self):
        """Ensures the credential audit CSV exists with headers."""
        if not os.path.exists(self.csv_file):
            with open(self.csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "Target", "Service", "Port", "User", "Password", "Result"])

    def check_socket(self, target, port):
        """Performs a lightweight TCP connect scan to find open ports before running heavy Nmap scans."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(self.dynamic_timeout)
            return port if s.connect_ex((target, port)) == 0 else None

    def audit_web_services(self, target, port):
        """
        Scans for common sensitive files and misconfigurations based on OWASP Top 10.
        Checks for .env files, git configs, and admin panels.
        """
        checks = [
            (".env", "A05:Security Misconfiguration", "High"),
            (".git/config", "A01:Broken Access Control", "High"),
            ("admin", "A01:Broken Access Control", "Medium"),
            ("backup.zip", "A05:Security Misconfiguration", "Medium"),
            ("phpinfo.php", "A05:Security Misconfiguration", "Low")
        ]
        results = []
        proto = "https" if port == 443 else "http"
        for path, cat, sev in checks:
            url = f"{proto}://{target}:{port}/{path}"
            try:
                r = requests.get(url, timeout=2, verify=False, allow_redirects=False)
                if r.status_code == 200:
                    results.append({'id': 'WEB-EXPOSED', 'severity': sev, 'owasp': cat, 'output': f"Found: {url}"})
            except: continue
        return results

    def brute_force_log(self, target, port, service):
        """Logs credential testing attempts (Placeholder logic for actual brute forcing)."""
        creds = [("admin", "admin"), ("root", "root")]
        for u, p in creds:
            with open(self.csv_file, 'a', newline='') as f:
                csv.writer(f).writerow([datetime.now(), target, service, port, u, p, "FAIL"])
        return []

    def run_scan(self, target, port_arg):
        """Main execution flow: Pre-scan -> Nmap Analysis -> Web Audit -> Database Save -> Report."""
        port_list = parse_ports(port_arg)
        logger.info(f"Socket pre-scan for {len(port_list)} ports...")
        
        # Phase 1: Fast multi-threaded discovery
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(self.check_socket, target, p) for p in port_list]
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res: open_ports.append(str(res))
        
        if not open_ports:
            return logger.info("No open ports found.")

        # Phase 2: Detailed Nmap service and vuln script scanning
        logger.info(f"Analyzing services on: {','.join(open_ports)}")
        self.nm.scan(hosts=target, ports=",".join(open_ports), arguments="-sV --script vuln")
        
        scan_results = {}
        previous_ports = self.db.get_last_scan_ports(target)

        for host in self.nm.all_hosts():
            h_info = {'hostname': self.nm[host].hostname(), 'status': 'up', 'ports': []}
            for proto in self.nm[host].all_protocols():
                for port in self.nm[host][proto].keys():
                    p_info = self.nm[host][proto][port]
                    service = (p_info.get('name') or "").lower()
                    
                    # Phase 3: Gather Nmap Scripting Engine (NSE) findings
                    vulns = [{'id': k, 'output': v, 'severity': 'High', 'owasp': 'A06:Vulnerable Components'} 
                             for k, v in p_info.get('script', {}).items()]
                    
                    # Phase 4: Additional Web/Auth Audits
                    if any(x in service for x in ['http', 'https', 'apache', 'nginx']) or port in [80, 443, 8080]:
                        vulns.extend(self.audit_web_services(host, port))
                    
                    if any(x in service for x in ['ssh', 'ftp', 'telnet']):
                        vulns.extend(self.brute_force_log(host, port, service))

                    h_info['ports'].append({
                        'port': port, 'protocol': proto, 'service': service,
                        'state': 'open', 'product': p_info.get('product'),
                        'version': p_info.get('version'), 'vulnerabilities': vulns,
                        'is_new': port not in previous_ports # Delta marking
                    })
            scan_results[host] = h_info
        
        self.db.save_results(scan_results)
        self.generate_report()

    def generate_report(self, filename="security_report.html"):
        """Generates a standalone, searchable HTML dashboard using embedded CSS and JS."""
        all_hosts = self.db.get_all_results_for_report()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Embedded UI Assets
        css = """
        body { font-family: 'Segoe UI', sans-serif; background: #f4f7f9; padding: 20px; }
        .container { max-width: 1200px; margin: auto; background: white; padding: 25px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .controls { margin-bottom: 20px; display: flex; gap: 10px; align-items: center; background: #eee; padding: 15px; border-radius: 5px; }
        input { padding: 10px; border: 1px solid #ccc; border-radius: 4px; flex-grow: 1; font-size: 16px; }
        .host-block { margin-bottom: 30px; border: 1px solid #dee2e6; border-radius: 5px; overflow: hidden; background: #fff; }
        .host-header { background: #00539b; color: white; padding: 12px 15px; display: flex; justify-content: space-between; }
        .new-port { background: #e6fffa; border-left: 5px solid #38b2ac; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #dee2e6; padding: 12px; text-align: left; }
        .vuln-tag { display: block; background: #fff5f5; color: #c53030; padding: 6px; margin-top: 4px; font-size: 0.85em; border-radius: 3px; border: 1px solid #feb2b2; }
        .owasp { font-weight: bold; color: #2c5282; }
        .hidden { display: none !important; }
        """

        js = """
        function filterHosts() {
            const input = document.getElementById('hostFilter').value.toLowerCase();
            const blocks = document.getElementsByClassName('host-block');
            let visibleCount = 0;
            for (let block of blocks) {
                const text = block.getAttribute('data-hostinfo').toLowerCase();
                if (text.includes(input)) {
                    block.classList.remove('hidden');
                    visibleCount++;
                } else {
                    block.classList.add('hidden');
                }
            }
            document.getElementById('visibleCount').innerText = visibleCount;
        }
        """
        
        # HTML Content Assembly
        html = f"""
        <html><head><style>{css}</style><script>{js}</script></head><body>
        <div class='container'>
            <h1>Network Security Master Report</h1>
            <p>Compiled: {now}</p>
            <div class='controls'>
                <strong>Filter Results:</strong>
                <input type='text' id='hostFilter' onkeyup='filterHosts()' placeholder='Search IP address or hostname...'>
                <span>Showing <span id='visibleCount'>{len(all_hosts)}</span> host(s)</span>
            </div>"""

        for host in all_hosts:
            host_meta = f"{host['ip_address']} {host['hostname']}"
            html += f"""
            <div class='host-block' data-hostinfo='{host_meta}'>
                <div class='host-header'>
                    <span>Host: {host['ip_address']} ({host['hostname'] or 'N/A'})</span>
                    <span>Last Scanned: {host['scan_timestamp']}</span>
                </div>
                <table>
                    <thead><tr><th>Port</th><th>Service</th><th>Version</th><th>Vulnerabilities</th></tr></thead>
                    <tbody>"""
            for p in host['ports']:
                row_class = "class='new-port'" if p.get('is_new') else ""
                vuln_html = ""
                for v in p['vulnerabilities']:
                    cat = f"<span class='owasp'>[{v.get('owasp_category','N/A')}]</span>"
                    vuln_html += f"<span class='vuln-tag'>{cat} <b>{v['vuln_id']}</b>: {v['description'][:200]}...</span>"
                
                html += f"""
                <tr {row_class}>
                    <td><b>{p['port_number']}/{p['protocol']}</b></td>
                    <td>{p['service_name']}</td>
                    <td>{p['product']} {p['version']}</td>
                    <td>{vuln_html if vuln_html else '<span style="color:green">No critical vulnerabilities found.</span>'}</td>
                </tr>"""
            html += "</tbody></table></div>"
            
        html += "</div></body></html>"
        with open(filename, "w") as f:
            f.write(html)
        logger.info(f"Interactive report generated: {filename}")

def main():
    """CLI Entrypoint."""
    parser = argparse.ArgumentParser(description="Master Port Scanner & Auditor")
    parser.add_argument('target', help="Target IP or Range (e.g., 192.168.1.1)")
    parser.add_argument('-p', '--ports', default="21,22,80,443,8080", help="Ports (e.g., 80,443 or 1-1024)")
    args = parser.parse_args()

    scanner = AdvancedPortScanner(PortScannerDB())
    scanner.run_scan(args.target, args.ports)

if __name__ == "__main__":
    main()