# IR-Tool: Incident Response Tool

A lightweight, cross-platform Python tool for collecting system information during incident response investigations. This tool helps security professionals quickly gather critical system data including processes, network connections, disk usage, and system configuration.

## Features

- **System Information Collection**: Gather OS details, CPU, memory, and boot time
- **Network Analysis**: Capture active connections and network interfaces
- **Process Monitoring**: List all running processes with CPU and memory usage
- **Disk Analysis**: View disk partitions and usage statistics
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

### Basic Usage

Collect all information and save as JSON:
```bash
python ir_tool.py
```

This will generate `ir_report.json` in the current directory.

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

### HTML Report
The HTML report provides a formatted, easy-to-read summary including:
- System overview with key metrics
- Disk partition information
- Active network connections
- Top processes by CPU usage

## Use Cases

- **Incident Response**: Quickly capture system state during security incidents
- **System Auditing**: Document system configuration and running processes
- **Performance Analysis**: Identify resource-intensive processes
- **Forensics**: Create point-in-time snapshots for investigation
- **Compliance**: Generate system inventory reports

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
- CPU and memory usage per process
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

## Requirements

- Python 3.6 or higher
- psutil library (automatically installed via requirements.txt)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available for use in incident response activities.

## Author

Created for incident response and security investigation purposes.

## Acknowledgments

- Built with [psutil](https://github.com/giampaolo/psutil) for cross-platform system information
- Designed for security professionals and incident responders