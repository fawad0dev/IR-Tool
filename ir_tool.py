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
import time
import sys
import copy
import webbrowser
import threading
import shutil
from http.server import HTTPServer, SimpleHTTPRequestHandler
from typing import Dict, List, Any, Optional
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
    def collect(cpu_interval: float = 0.1) -> List[Dict[str, Any]]:
        """Collect information about running processes
        
        Args:
            cpu_interval: Time interval to measure CPU usage (0 for instant, >0 for accurate)
        """
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'create_time', 'memory_percent']):
            try:
                pinfo = proc.info
                pinfo['create_time'] = datetime.datetime.fromtimestamp(pinfo['create_time']).isoformat()
                # Get actual CPU usage instead of placeholder
                try:
                    pinfo['cpu_percent'] = proc.cpu_percent(interval=cpu_interval)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pinfo['cpu_percent'] = 0.0
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


class QuietHTTPRequestHandler(SimpleHTTPRequestHandler):
    """HTTP request handler with minimal logging"""
    
    def log_message(self, format, *args):
        """Suppress HTTP request logs"""
        pass


class MonitorWebServer:
    """Simple web server for monitoring dashboard"""
    
    def __init__(self, port: int = 8000):
        self.port = port
        self.server = None
        self.thread = None
        self.running = False
    
    def start(self):
        """Start the web server in a background thread"""
        self.server = HTTPServer(('localhost', self.port), QuietHTTPRequestHandler)
        self.running = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        print(f"[+] Web dashboard server started at http://localhost:{self.port}")
    
    def stop(self):
        """Stop the web server"""
        if self.server:
            self.server.shutdown()
            self.running = False
            print("[*] Web dashboard server stopped")


class IRTool:
    """Main Incident Response Tool class"""
    
    # Configuration constants
    MAX_CONNECTIONS_IN_REPORT = 50
    MAX_PROCESSES_IN_REPORT = 25
    
    def __init__(self):
        self.timestamp = datetime.datetime.now().isoformat()
        self.data = {}
        self.previous_data = {}  # Store previous snapshot for comparison
        self.system_collector = SystemCollector()
        self.network_collector = NetworkCollector()
        self.process_collector = ProcessCollector()
        self.disk_collector = DiskCollector()
        # Only initialize HTML renderer if needed
        self.html_renderer = None
    
    def collect_all(self, cpu_interval: float = 0.1):
        """Collect all available information
        
        Args:
            cpu_interval: Time to measure CPU usage (0 for instant, >0 for accurate)
        """
        print("[*] Collecting system information...")
        self.data['system'] = SystemCollector.collect()
        
        print("[*] Collecting network information...")
        self.data['network'] = NetworkCollector.collect()
        
        print("[*] Collecting process information...")
        self.data['processes'] = ProcessCollector.collect(cpu_interval=cpu_interval)
        
        print("[*] Collecting disk information...")
        self.data['disk'] = DiskCollector.collect()
        
        self.data['metadata'] = {
            "timestamp": self.timestamp,
            "tool": "IR-Tool",
            "version": "1.2.0"
        }
    
    def detect_changes(self) -> Dict[str, Any]:
        """Detect changes between current and previous snapshots"""
        if not self.previous_data:
            return {"message": "No previous data for comparison"}
        
        changes = {}
        
        # Detect new and terminated processes
        if 'processes' in self.data and 'processes' in self.previous_data:
            current_pids = {p['pid'] for p in self.data['processes']}
            previous_pids = {p['pid'] for p in self.previous_data['processes']}
            
            new_pids = current_pids - previous_pids
            terminated_pids = previous_pids - current_pids
            
            new_processes = [p for p in self.data['processes'] if p['pid'] in new_pids]
            terminated_processes = [p for p in self.previous_data['processes'] if p['pid'] in terminated_pids]
            
            changes['new_processes'] = new_processes
            changes['terminated_processes'] = terminated_processes
            changes['new_process_count'] = len(new_processes)
            changes['terminated_process_count'] = len(terminated_processes)
        
        # Detect new network connections
        if 'network' in self.data and 'network' in self.previous_data:
            current_conns = {
                f"{c.get('local_addr', 'N/A')}:{c.get('remote_addr', 'N/A')}:{c.get('status', '')}" 
                for c in self.data['network'].get('connections', [])
                if 'error' not in c and c.get('local_addr') and c.get('remote_addr')
            }
            previous_conns = {
                f"{c.get('local_addr', 'N/A')}:{c.get('remote_addr', 'N/A')}:{c.get('status', '')}" 
                for c in self.previous_data['network'].get('connections', [])
                if 'error' not in c and c.get('local_addr') and c.get('remote_addr')
            }
            
            new_connections = current_conns - previous_conns
            changes['new_connection_count'] = len(new_connections)
            changes['closed_connection_count'] = len(previous_conns - current_conns)
        
        return changes
    
    def get_high_resource_processes(self, cpu_threshold: float = 50.0, 
                                   memory_threshold: float = 50.0) -> Dict[str, List]:
        """Identify processes using high resources
        
        Args:
            cpu_threshold: CPU usage percentage threshold
            memory_threshold: Memory usage percentage threshold
        """
        high_cpu = [
            p for p in self.data.get('processes', [])
            if p.get('cpu_percent', 0) > cpu_threshold
        ]
        high_memory = [
            p for p in self.data.get('processes', [])
            if p.get('memory_percent', 0) > memory_threshold
        ]
        
        return {
            'high_cpu_processes': high_cpu,
            'high_memory_processes': high_memory
        }
    
    def save_json(self, filename: str):
        """Save collected data as JSON"""
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=2)
        print(f"[+] JSON report saved to: {filename}")
    
    def save_html(self, filename):
        """Save collected data as HTML report using template"""
        try:
            if self.html_renderer is None:
                self.html_renderer = HTMLRenderer()
            html_content = self.html_renderer.render(self.data)
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"[+] HTML report saved to {filename}")
        except FileNotFoundError as e:
            print(f"[!] Warning: Could not generate HTML report - {e}")
            print(f"[!] HTML template is missing. JSON output is still available.")
    
    def display_summary(self, show_changes: bool = False):
        """Display a summary of collected data to console"""
        print("\n" + "=" * 60)
        print("SYSTEM SUMMARY")
        print("=" * 60)
        
        if 'system' in self.data:
            sys_data = self.data['system']
            print(f"Hostname: {sys_data.get('hostname', 'N/A')}")
            print(f"Platform: {sys_data.get('platform', 'N/A')} {sys_data.get('platform_release', '')}")
            print(f"CPU Usage: {sys_data.get('cpu_percent', 0):.1f}%")
            print(f"Memory Usage: {sys_data.get('memory_percent', 0):.1f}%")
        
        if 'processes' in self.data:
            print(f"\nTotal Processes: {len(self.data['processes'])}")
            
            # Show top CPU processes
            top_cpu = sorted(self.data['processes'], 
                           key=lambda x: x.get('cpu_percent', 0), 
                           reverse=True)[:5]
            if top_cpu and top_cpu[0].get('cpu_percent', 0) > 0:
                print("\nTop CPU Processes:")
                for proc in top_cpu:
                    print(f"  {proc['name']} (PID: {proc['pid']}): {proc['cpu_percent']:.1f}%")
        
        if 'network' in self.data:
            connections = [c for c in self.data['network'].get('connections', []) if 'error' not in c]
            print(f"\nActive Network Connections: {len(connections)}")
        
        if show_changes:
            changes = self.detect_changes()
            if 'message' not in changes:
                print("\n" + "=" * 60)
                print("CHANGES DETECTED")
                print("=" * 60)
                print(f"New Processes: {changes.get('new_process_count', 0)}")
                print(f"Terminated Processes: {changes.get('terminated_process_count', 0)}")
                print(f"New Connections: {changes.get('new_connection_count', 0)}")
                print(f"Closed Connections: {changes.get('closed_connection_count', 0)}")
                
                if changes.get('new_processes'):
                    print("\nNew Processes:")
                    for proc in changes['new_processes'][:10]:
                        print(f"  {proc['name']} (PID: {proc['pid']})")
        
        print("=" * 60 + "\n")
    
    def monitor(self, interval: int = 5, duration: Optional[int] = None, 
                output_file: Optional[str] = None, web_mode: bool = False, 
                web_port: int = 8000):
        """Continuous monitoring mode
        
        Args:
            interval: Seconds between updates
            duration: Total monitoring duration in seconds (None for infinite)
            output_file: Optional file to log snapshots
            web_mode: Enable web dashboard for visual monitoring
            web_port: Port for web dashboard (default: 8000)
        """
        print("=" * 60)
        print("IR-Tool: Continuous Monitoring Mode")
        print("=" * 60)
        print(f"Update Interval: {interval} seconds")
        print(f"Duration: {'Infinite (Ctrl+C to stop)' if duration is None else f'{duration} seconds'}")
        if web_mode:
            print(f"Web Dashboard: http://localhost:{web_port}")
        print("=" * 60 + "\n")
        
        start_time = time.time()
        iteration = 0
        snapshots = []
        web_server = None
        
        # Start web server if web mode is enabled
        if web_mode:
            try:
                # Copy dashboard template to current directory
                template_dir = os.path.join(os.path.dirname(__file__), 'templates')
                dashboard_file = os.path.join(template_dir, 'monitor_dashboard.html')
                
                if os.path.exists(dashboard_file):
                    shutil.copy(dashboard_file, 'monitor_dashboard.html')
                    print("[+] Dashboard template copied to current directory")
                else:
                    print("[!] Warning: Dashboard template not found, web mode may not work properly")
                
                web_server = MonitorWebServer(port=web_port)
                web_server.start()
                
                # Open browser automatically (give server time to start)
                time.sleep(1)
                webbrowser.open(f'http://localhost:{web_port}/monitor_dashboard.html')
                print("[+] Opening web dashboard in browser...")
                print()
            except Exception as e:
                print(f"[!] Warning: Could not start web server: {e}")
                print("[*] Continuing in console mode...")
                web_mode = False
        
        try:
            while True:
                iteration += 1
                self.timestamp = datetime.datetime.now().isoformat()
                
                if not web_mode:
                    print(f"[{self.timestamp}] Update #{iteration}")
                
                # Collect data with optimized CPU interval for monitoring
                self.collect_all(cpu_interval=0.1)  # Small interval for reasonable accuracy and speed
                
                # Get changes information
                changes = self.detect_changes() if iteration > 1 else {}
                
                # Write data to JSON file for web dashboard
                if web_mode:
                    web_data = {
                        'timestamp': self.timestamp,
                        'iteration': iteration,
                        'system': self.data.get('system', {}),
                        'processes': self.data.get('processes', []),
                        'network': self.data.get('network', {}),
                        'disk': self.data.get('disk', {}),
                        'changes': changes
                    }
                    with open('monitor_data.json', 'w') as f:
                        json.dump(web_data, f, indent=2)
                    
                    # Print minimal console output in web mode
                    print(f"[{self.timestamp}] Update #{iteration} - View dashboard at http://localhost:{web_port}/monitor_dashboard.html")
                else:
                    # Display summary in console mode
                    self.display_summary(show_changes=(iteration > 1))
                
                # Check for high resource usage
                alerts = self.get_high_resource_processes(cpu_threshold=70.0, memory_threshold=70.0)
                if alerts['high_cpu_processes'] or alerts['high_memory_processes']:
                    if not web_mode:
                        print("*** ALERT: High Resource Usage Detected! ***")
                        for proc in alerts['high_cpu_processes'][:3]:
                            print(f"  High CPU: {proc['name']} (PID: {proc['pid']}) - {proc['cpu_percent']:.1f}%")
                        for proc in alerts['high_memory_processes'][:3]:
                            print(f"  High Memory: {proc['name']} (PID: {proc['pid']}) - {proc['memory_percent']:.1f}%")
                        print()
                
                # Store snapshot
                if output_file:
                    snapshot = {
                        'iteration': iteration,
                        'timestamp': self.timestamp,
                        'data': self.data
                    }
                    snapshots.append(snapshot)
                
                # Store for comparison (use deep copy to avoid reference issues)
                self.previous_data = copy.deepcopy(self.data)
                
                # Check if duration exceeded
                if duration and (time.time() - start_time) >= duration:
                    print(f"[*] Monitoring duration of {duration} seconds reached.")
                    break
                
                # Wait for next iteration
                if not web_mode:
                    print(f"[*] Waiting {interval} seconds for next update...")
                    print()
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n[*] Monitoring stopped by user.")
        finally:
            # Stop web server if running
            if web_server and web_server.running:
                web_server.stop()
        
        # Save all snapshots if output file specified
        if output_file and snapshots:
            with open(output_file, 'w') as f:
                json.dump({
                    'monitoring_session': {
                        'start_time': datetime.datetime.fromtimestamp(start_time).isoformat(),
                        'end_time': datetime.datetime.now().isoformat(),
                        'total_iterations': iteration,
                        'snapshots': snapshots
                    }
                }, f, indent=2)
            print(f"[+] Monitoring log saved to: {output_file}")
        
        print("[+] Monitoring session complete!")
    
def main():
    parser = argparse.ArgumentParser(
        description='IR-Tool: Incident Response Tool for collecting system information',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ir_tool.py                          # Collect all info and save as JSON
  python ir_tool.py --html report.html       # Generate HTML report
  python ir_tool.py --json data.json --html report.html  # Save both formats
  python ir_tool.py --monitor --interval 10  # Monitor continuously every 10 seconds
  python ir_tool.py --monitor --interval 5 --duration 60  # Monitor for 60 seconds
  python ir_tool.py --monitor --web          # Monitor with visual web dashboard
  python ir_tool.py --monitor --web --port 8080  # Web dashboard on custom port
  
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
    
    parser.add_argument(
        '--monitor',
        action='store_true',
        help='Enable continuous monitoring mode'
    )
    
    parser.add_argument(
        '--interval',
        type=int,
        default=5,
        help='Update interval in seconds for monitoring mode (default: 5)'
    )
    
    parser.add_argument(
        '--duration',
        type=int,
        help='Total monitoring duration in seconds (default: infinite, stop with Ctrl+C)'
    )
    
    parser.add_argument(
        '--log',
        type=str,
        help='Save monitoring snapshots to a JSON log file'
    )
    
    parser.add_argument(
        '--web',
        action='store_true',
        help='Enable web dashboard for visual monitoring (only works with --monitor)'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=8000,
        help='Port for web dashboard (default: 8000)'
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("IR-Tool: Incident Response Tool v1.2.0")
    print("=" * 60)
    print()
    
    # Initialize tool
    tool = IRTool()
    
    # Check if monitoring mode is enabled
    if args.monitor:
        tool.monitor(
            interval=args.interval,
            duration=args.duration,
            output_file=args.log,
            web_mode=args.web,
            web_port=args.port
        )
    else:
        # Single snapshot mode
        tool.collect_all()
        
        print()
        print("[*] Collection complete!")
        print()
        
        # Display summary
        tool.display_summary()
        
        # Save reports
        if not args.no_json:
            tool.save_json(args.json)
        
        if args.html:
            tool.save_html(args.html)
        
        print()
        print("[+] Done!")


if __name__ == "__main__":
    main()
