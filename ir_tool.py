#!/usr/bin/env python3
"""
IR-Tool: Incident Response Tool
A lightweight tool for collecting system information during incident response
"""

import psutil
import platform
import socket
import json
import os
import datetime
import argparse
from typing import Dict, List, Any


class SystemCollector:
    """Collect system information"""
    
    @staticmethod
    def collect() -> Dict[str, Any]:
        """Collect basic system information"""
        return {
            "hostname": socket.gethostname(),
            "platform": platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "boot_time": datetime.datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            "cpu_count": psutil.cpu_count(logical=True),
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_total": psutil.virtual_memory().total,
            "memory_available": psutil.virtual_memory().available,
            "memory_percent": psutil.virtual_memory().percent,
        }


class NetworkCollector:
    """Collect network information"""
    
    @staticmethod
    def collect() -> Dict[str, Any]:
        """Collect network connections and interface information"""
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                connections.append({
                    "fd": conn.fd,
                    "family": str(conn.family),
                    "type": str(conn.type),
                    "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    "status": conn.status,
                    "pid": conn.pid
                })
        except (psutil.AccessDenied, PermissionError):
            connections.append({"error": "Permission denied - run with elevated privileges"})
        
        interfaces = {}
        for interface, addrs in psutil.net_if_addrs().items():
            interfaces[interface] = []
            for addr in addrs:
                interfaces[interface].append({
                    "family": str(addr.family),
                    "address": addr.address,
                    "netmask": addr.netmask,
                    "broadcast": addr.broadcast
                })
        
        return {
            "connections": connections,
            "interfaces": interfaces,
            "io_counters": {k: {
                "bytes_sent": v.bytes_sent,
                "bytes_recv": v.bytes_recv,
                "packets_sent": v.packets_sent,
                "packets_recv": v.packets_recv
            } for k, v in psutil.net_io_counters(pernic=True).items()}
        }


class ProcessCollector:
    """Collect process information"""
    
    @staticmethod
    def collect() -> List[Dict[str, Any]]:
        """Collect information about running processes"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'create_time', 'cpu_percent', 'memory_percent']):
            try:
                pinfo = proc.info
                pinfo['create_time'] = datetime.datetime.fromtimestamp(pinfo['create_time']).isoformat()
                processes.append(pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        return sorted(processes, key=lambda x: x.get('cpu_percent', 0), reverse=True)


class DiskCollector:
    """Collect disk and filesystem information"""
    
    @staticmethod
    def collect() -> Dict[str, Any]:
        """Collect disk usage and partition information"""
        partitions = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                partitions.append({
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "total": usage.total,
                    "used": usage.used,
                    "free": usage.free,
                    "percent": usage.percent
                })
            except PermissionError:
                partitions.append({
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "error": "Permission denied"
                })
        
        return {
            "partitions": partitions,
            "io_counters": {k: {
                "read_count": v.read_count,
                "write_count": v.write_count,
                "read_bytes": v.read_bytes,
                "write_bytes": v.write_bytes
            } for k, v in psutil.disk_io_counters(perdisk=True).items()}
        }


class IRTool:
    """Main Incident Response Tool class"""
    
    def __init__(self):
        self.timestamp = datetime.datetime.now().isoformat()
        self.data = {}
    
    def collect_all(self):
        """Collect all available information"""
        print("[*] Collecting system information...")
        self.data['system'] = SystemCollector.collect()
        
        print("[*] Collecting network information...")
        self.data['network'] = NetworkCollector.collect()
        
        print("[*] Collecting process information...")
        self.data['processes'] = ProcessCollector.collect()
        
        print("[*] Collecting disk information...")
        self.data['disk'] = DiskCollector.collect()
        
        self.data['metadata'] = {
            "timestamp": self.timestamp,
            "tool": "IR-Tool",
            "version": "1.0.0"
        }
    
    def save_json(self, filename: str):
        """Save collected data as JSON"""
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=2)
        print(f"[+] JSON report saved to: {filename}")
    
    def save_html(self, filename: str):
        """Save collected data as HTML report"""
        html = self._generate_html()
        with open(filename, 'w') as f:
            f.write(html)
        print(f"[+] HTML report saved to: {filename}")
    
    def _generate_html(self) -> str:
        """Generate HTML report"""
        system = self.data.get('system', {})
        network = self.data.get('network', {})
        processes = self.data.get('processes', [])
        disk = self.data.get('disk', {})
        metadata = self.data.get('metadata', {})
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>IR-Tool Report - {system.get('hostname', 'Unknown')}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #4CAF50;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #4CAF50;
            margin-top: 30px;
            border-bottom: 2px solid #ddd;
            padding-bottom: 5px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #4CAF50;
            color: white;
            font-weight: bold;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .info-box {{
            background-color: #e8f5e9;
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid #4CAF50;
        }}
        .warning {{
            background-color: #fff3cd;
            border-left-color: #ffc107;
        }}
        .metadata {{
            color: #666;
            font-size: 0.9em;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Incident Response Report</h1>
        
        <div class="metadata">
            <strong>Report Generated:</strong> {metadata.get('timestamp', 'N/A')}<br>
            <strong>Tool:</strong> {metadata.get('tool', 'N/A')} v{metadata.get('version', 'N/A')}
        </div>
        
        <h2>System Information</h2>
        <div class="info-box">
            <strong>Hostname:</strong> {system.get('hostname', 'N/A')}<br>
            <strong>Platform:</strong> {system.get('platform', 'N/A')} {system.get('platform_release', 'N/A')}<br>
            <strong>Architecture:</strong> {system.get('architecture', 'N/A')}<br>
            <strong>Processor:</strong> {system.get('processor', 'N/A')}<br>
            <strong>Boot Time:</strong> {system.get('boot_time', 'N/A')}<br>
            <strong>CPU Count:</strong> {system.get('cpu_count', 'N/A')}<br>
            <strong>CPU Usage:</strong> {system.get('cpu_percent', 'N/A')}%<br>
            <strong>Memory Total:</strong> {self._format_bytes(system.get('memory_total', 0))}<br>
            <strong>Memory Available:</strong> {self._format_bytes(system.get('memory_available', 0))}<br>
            <strong>Memory Usage:</strong> {system.get('memory_percent', 'N/A')}%
        </div>
        
        <h2>Disk Information</h2>
        <table>
            <tr>
                <th>Device</th>
                <th>Mount Point</th>
                <th>Type</th>
                <th>Total</th>
                <th>Used</th>
                <th>Free</th>
                <th>Usage %</th>
            </tr>
"""
        
        for part in disk.get('partitions', []):
            if 'error' not in part:
                html += f"""            <tr>
                <td>{part.get('device', 'N/A')}</td>
                <td>{part.get('mountpoint', 'N/A')}</td>
                <td>{part.get('fstype', 'N/A')}</td>
                <td>{self._format_bytes(part.get('total', 0))}</td>
                <td>{self._format_bytes(part.get('used', 0))}</td>
                <td>{self._format_bytes(part.get('free', 0))}</td>
                <td>{part.get('percent', 'N/A')}%</td>
            </tr>
"""
        
        html += """        </table>
        
        <h2>Network Connections</h2>
        <table>
            <tr>
                <th>Protocol</th>
                <th>Local Address</th>
                <th>Remote Address</th>
                <th>Status</th>
                <th>PID</th>
            </tr>
"""
        
        for conn in network.get('connections', [])[:50]:  # Limit to first 50
            if 'error' not in conn:
                html += f"""            <tr>
                <td>{conn.get('type', 'N/A')}</td>
                <td>{conn.get('local_addr', 'N/A')}</td>
                <td>{conn.get('remote_addr', 'N/A') or '-'}</td>
                <td>{conn.get('status', 'N/A')}</td>
                <td>{conn.get('pid', 'N/A') or '-'}</td>
            </tr>
"""
        
        html += """        </table>
        
        <h2>Top Processes (by CPU)</h2>
        <table>
            <tr>
                <th>PID</th>
                <th>Name</th>
                <th>Username</th>
                <th>Status</th>
                <th>CPU %</th>
                <th>Memory %</th>
                <th>Started</th>
            </tr>
"""
        
        for proc in processes[:25]:  # Top 25 processes
            html += f"""            <tr>
                <td>{proc.get('pid', 'N/A')}</td>
                <td>{proc.get('name', 'N/A')}</td>
                <td>{proc.get('username', 'N/A')}</td>
                <td>{proc.get('status', 'N/A')}</td>
                <td>{proc.get('cpu_percent', 0):.1f}%</td>
                <td>{proc.get('memory_percent', 0):.1f}%</td>
                <td>{proc.get('create_time', 'N/A')}</td>
            </tr>
"""
        
        html += """        </table>
        
        <div class="metadata">
            <p><strong>Note:</strong> This report contains a snapshot of system information at the time of collection. 
            For ongoing investigations, collect multiple snapshots over time.</p>
        </div>
    </div>
</body>
</html>
"""
        return html
    
    @staticmethod
    def _format_bytes(bytes_value: int) -> str:
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"


def main():
    parser = argparse.ArgumentParser(
        description='IR-Tool: Incident Response Tool for collecting system information',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ir_tool.py                          # Collect all info and save as JSON
  python ir_tool.py --html report.html       # Generate HTML report
  python ir_tool.py --json data.json --html report.html  # Save both formats
  
Note: Run with elevated privileges (sudo/admin) for complete information.
        """
    )
    
    parser.add_argument(
        '--json',
        type=str,
        default='ir_report.json',
        help='Output JSON file (default: ir_report.json)'
    )
    
    parser.add_argument(
        '--html',
        type=str,
        help='Output HTML file (optional)'
    )
    
    parser.add_argument(
        '--no-json',
        action='store_true',
        help='Skip JSON output'
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("IR-Tool: Incident Response Tool v1.0.0")
    print("=" * 60)
    print()
    
    # Initialize and collect data
    tool = IRTool()
    tool.collect_all()
    
    print()
    print("[*] Collection complete!")
    print()
    
    # Save reports
    if not args.no_json:
        tool.save_json(args.json)
    
    if args.html:
        tool.save_html(args.html)
    
    print()
    print("[+] Done!")


if __name__ == "__main__":
    main()
