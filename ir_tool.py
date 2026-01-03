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
from html_renderer import HTMLRenderer


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
            "cpu_percent": psutil.cpu_percent(interval=0.1),
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
        for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'create_time', 'memory_percent']):
            try:
                pinfo = proc.info
                pinfo['create_time'] = datetime.datetime.fromtimestamp(pinfo['create_time']).isoformat()
                pinfo['cpu_percent'] = 0.0  # Set to 0 for performance; can be enhanced later
                processes.append(pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        return sorted(processes, key=lambda x: x.get('memory_percent', 0), reverse=True)


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
    
    # Configuration constants
    MAX_CONNECTIONS_IN_REPORT = 50
    MAX_PROCESSES_IN_REPORT = 25
    
    def __init__(self):
        self.timestamp = datetime.datetime.now().isoformat()
        self.data = {}
        self.system_collector = SystemCollector()
        self.network_collector = NetworkCollector()
        self.process_collector = ProcessCollector()
        self.disk_collector = DiskCollector()
        self.html_renderer = HTMLRenderer()
    
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
    
    def save_html(self, filename):
        """Save collected data as HTML report using template"""
        html_content = self.html_renderer.render(self.data)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"HTML report saved to {filename}")
    
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
