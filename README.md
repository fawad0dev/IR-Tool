# IR-Tool: Incident Response Tool

A lightweight, cross-platform Python tool for collecting and monitoring system information during incident response investigations. This tool helps security professionals quickly gather critical system data including processes, network connections, disk usage, and system configuration with real-time monitoring capabilities.

## Features

- **System Information Collection**: Gather OS details, CPU, memory, and boot time
- **Network Analysis**: Capture active connections and network interfaces
- **Process Monitoring**: List all running processes with actual CPU and memory usage
- **Disk Analysis**: View disk partitions and usage statistics
- **Continuous Monitoring Mode**: Track system changes in real-time with periodic updates
- **Visual Web Dashboard**: Real-time monitoring with beautiful, auto-refreshing web interface
- **Change Detection**: Identify new/terminated processes and network connections
- **Resource Alerts**: Automatic alerts for high CPU and memory usage
- **Multiple Output Formats**: Generate both JSON (for parsing) and HTML (for reporting) outputs
- **Cross-Platform**: Works on Linux, Windows, and macOS

## Installation

1. Clone the repository:
```bash
git clone https://github.com/fawad0dev/IR-Tool.git
cd IR-Tool
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Single Snapshot Mode

Collect all information once and save as JSON:
```bash
python ir_tool.py
```

This will generate `ir_report.json` in the current directory and display a summary.

### Generate HTML Report

Create a human-readable HTML report:
```bash
python ir_tool.py --html report.html
```

### Custom Output Files

Specify custom filenames:
```bash
python ir_tool.py --json my_data.json --html my_report.html
```

### Skip JSON Output

Generate only HTML report:
```bash
python ir_tool.py --no-json --html report.html
```

### Continuous Monitoring Mode

Monitor system continuously with periodic updates:
```bash
python ir_tool.py --monitor
```

Monitor with custom update interval (in seconds):
```bash
python ir_tool.py --monitor --interval 10
```

Monitor for a specific duration:
```bash
python ir_tool.py --monitor --interval 5 --duration 60
```

Save monitoring snapshots to a log file:
```bash
python ir_tool.py --monitor --interval 5 --log monitoring_session.json
```

### Visual Monitoring with Web Dashboard

Enable real-time visual monitoring with an interactive web dashboard:
```bash
python ir_tool.py --monitor --web
```

The web dashboard provides:
- **Live Updates**: Auto-refreshing display of system metrics
- **Visual Charts**: Progress bars for CPU and memory usage
- **Color-Coded Alerts**: Warnings for high resource usage
- **Change Detection**: Visual indicators for new/terminated processes
- **Network Overview**: Real-time connection monitoring
- **Modern UI**: Beautiful, responsive dashboard with gradient design

Use a custom port for the web server:
```bash
python ir_tool.py --monitor --web --port 8080
```

The dashboard will automatically open in your default browser and update every 2 seconds with fresh data.

Stop monitoring anytime with `Ctrl+C`.

### Run with Elevated Privileges

For complete network connection information (including PIDs), run with elevated privileges:

**Linux/macOS:**
```bash
sudo python ir_tool.py
```

**Windows (PowerShell as Administrator):**
```powershell
python ir_tool.py
```

## Monitoring Features

### Real-Time Updates
In monitoring mode, the tool continuously collects system information and displays:
- Current system metrics (CPU, memory usage)
- Top CPU-consuming processes
- Active network connections
- Changes from previous snapshots

### Change Detection
The tool automatically detects and reports:
- New processes started since last update
- Terminated processes
- New network connections established
- Closed network connections

### Resource Alerts
Automatic alerts for:
- Processes using >70% CPU
- Processes using >70% memory
- Helps quickly identify resource-intensive or potentially malicious processes

## Output Examples

### JSON Output
The JSON output contains structured data suitable for automated analysis:
```json
{
  "system": {
    "hostname": "example-host",
    "platform": "Linux",
    "cpu_count": 4,
    "memory_percent": 45.2
  },
  "processes": [...],
  "network": {...},
  "disk": {...}
}
```

### Monitoring Log
When using `--log`, captures multiple snapshots over time:
```json
{
  "monitoring_session": {
    "start_time": "2026-01-03T12:00:00",
    "end_time": "2026-01-03T12:05:00",
    "total_iterations": 60,
    "snapshots": [...]
  }
}
```

### HTML Report
The HTML report provides a formatted, easy-to-read summary including:
- System overview with key metrics
- Disk partition information
- Active network connections
- Top processes by CPU usage

## Use Cases

- **Incident Response**: Quickly capture system state during security incidents and monitor for suspicious activities
- **System Auditing**: Document system configuration and running processes
- **Performance Analysis**: Identify resource-intensive processes in real-time
- **Forensics**: Create point-in-time snapshots for investigation
- **Compliance**: Generate system inventory reports
- **Threat Hunting**: Monitor for new processes and network connections that may indicate compromise
- **Baseline Comparison**: Track changes in system behavior over time

## Collected Information

### System Module
- Hostname and platform details
- CPU and memory statistics
- Boot time and uptime
- System architecture

### Network Module
- Active network connections
- Network interfaces and addresses
- Network I/O statistics
- Protocol information

### Process Module
- All running processes
- Process IDs (PIDs)
- Real-time CPU and memory usage per process
- Process start times
- Process owners

### Disk Module
- Disk partitions and mount points
- Filesystem types
- Storage capacity and usage
- Disk I/O statistics

## Security Considerations

- **Sensitive Data**: Reports may contain sensitive system information. Handle with care.
- **Privileges**: Some data requires elevated privileges to collect completely.
- **Storage**: Store reports securely and delete when no longer needed.
- **Privacy**: Be aware of privacy implications when collecting user information.
- **Monitoring**: Continuous monitoring can generate large log files; manage disk space appropriately.

## Requirements

- Python 3.6 or higher
- psutil library (automatically installed via requirements.txt)

## What's New in v1.2.0

- ✨ **Visual Web Dashboard**: Real-time monitoring with beautiful, auto-refreshing web interface
- ✨ **Live System Metrics**: Interactive dashboard with progress bars and color-coded alerts
- ✨ **Auto-Refresh**: Dashboard updates every 2 seconds with fresh data
- ✨ **Modern UI**: Gradient design with responsive layout
- ✨ **Change Visualization**: Visual indicators for new/terminated processes and connections

## What's New in v1.1.0

- ✨ **Continuous Monitoring Mode**: Track system changes in real-time
- ✨ **Actual CPU Usage**: Processes now show real CPU usage instead of 0%
- ✨ **Change Detection**: Identify new/terminated processes and connections
- ✨ **Resource Alerts**: Automatic alerts for high resource usage
- ✨ **Console Summary**: Rich summary output in terminal
- ✨ **Monitoring Logs**: Save multiple snapshots to JSON for analysis

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available for use in incident response activities.

## Author

Created for incident response and security investigation purposes.

## Acknowledgments

- Built with [psutil](https://github.com/giampaolo/psutil) for cross-platform system information
- Designed for security professionals and incident responders