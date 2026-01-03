from pathlib import Path

class HTMLRenderer:
    def __init__(self, template_path='templates/report_template.html'):
        self.template_path = Path(template_path)
        self.template = self._load_template()
    
    def _load_template(self):
        """Load HTML template from file"""
        if self.template_path.exists():
            return self.template_path.read_text(encoding='utf-8')
        else:
            raise FileNotFoundError(f"Template not found: {self.template_path}")
    
    def _format_bytes(self, bytes_value):
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"
    
    def _generate_system_info(self, system_info):
        """Generate system information HTML"""
        html = ""
        for key, value in system_info.items():
            html += f'<div class="info-box"><strong>{key.replace("_", " ").title()}:</strong> {value}</div>\n'
        return html
    
    def _generate_network_connections(self, connections):
        """Generate network connections table rows"""
        html = ""
        for conn in connections[:50]:  # Limit to 50
            html += f"""
                <tr>
                    <td>{str(conn.get('family', 'N/A')).replace('AddressFamily.', '')}</td>
                    <td>{str(conn.get('type', 'N/A')).replace('SocketKind.', '')}</td>
                    <td>{conn.get('local_addr', 'N/A')}</td>
                    <td>{conn.get('remote_addr', 'N/A')}</td>
                    <td>{conn.get('status', 'N/A')}</td>
                    <td>{conn.get('pid', 'N/A')}</td>
                </tr>
            """
        return html
    
    def _generate_network_interfaces(self, interfaces):
        """Generate network interfaces table rows"""
        html = ""
        for iface, data in interfaces.items():
            if isinstance(data, dict):
                ip = data.get('ip_address', 'N/A')
                sent = self._format_bytes(data.get('bytes_sent', 0))
                recv = self._format_bytes(data.get('bytes_recv', 0))
                html += f"""
                    <tr>
                        <td>{iface}</td>
                        <td>{ip}</td>
                        <td>{sent}</td>
                        <td>{recv}</td>
                    </tr>
                """
        return html
    
    def _generate_processes(self, processes):
        """Generate processes table rows"""
        html = ""
        for proc in processes[:25]:  # Top 25
            html += f"""
                <tr>
                    <td>{proc.get('create_time', 'N/A')}</td>
                    <td>{proc.get('username', 'N/A')}</td>
                    <td>{proc.get('pid', 'N/A')}</td>
                    <td>{proc.get('name', 'N/A')}</td>
                    <td>{proc.get('memory_percent', 0):.2f}%</td>
                    <td>{proc.get('cpu_percent', 0):.1f}%</td>
                    <td>{proc.get('status', 'N/A')}</td>
                </tr>
            """
        return html
    
    def _generate_disk_partitions(self, partitions):
        """Generate disk partitions table rows"""
        html = ""
        for part in partitions['partitions']:
            html += f"""
                <tr>
                    <td>{part.get('device', 'N/A')}</td>
                    <td>{part.get('mountpoint', 'N/A')}</td>
                    <td>{part.get('fstype', 'N/A')}</td>
                    <td>{self._format_bytes(part.get('total', 0))}</td>
                    <td>{self._format_bytes(part.get('used', 0))}</td>
                    <td>{self._format_bytes(part.get('free', 0))}</td>
                    <td>{part.get('percent', 0):.1f}%</td>
                </tr>
            """
        return html
    
    def render(self, data):
        """Render complete HTML report from data"""
        html = self.template
        
        # Replace placeholders
        html = html.replace('{{timestamp}}', data.get('timestamp', 'N/A'))
        html = html.replace('{{system_info}}', 
                          self._generate_system_info(data.get('system', {})))
        html = html.replace('{{network_connections}}', 
                          self._generate_network_connections(data.get('network', {}).get('connections', [])))
        html = html.replace('{{network_interfaces}}', 
                          self._generate_network_interfaces(data.get('network', {}).get('interfaces', {})))
        html = html.replace('{{processes}}', 
                          self._generate_processes(data.get('processes', [])))
        html = html.replace('{{disk_partitions}}', 
                          self._generate_disk_partitions(data.get('disk', [])))
        
        return html