import os
import sys
import json
import time
import socket
from datetime import datetime
from collections import defaultdict
from threading import Thread, Event
from rich.console import Console
from rich.table import Table
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

class HotspotMonitor:
    def __init__(self):
        self.console = Console()
        self.devices = defaultdict(lambda: {
            'ip': '',
            'mac': 'Unknown',
            'hostname': '',
            'sent_bytes': 0,
            'recv_bytes': 0,
            'protocols': set(),
            'domains': set(),
            'last_activity': datetime.now()
        })
        self.running = False
        self.log_file = "hotspot_traffic.log"
        self.traffic_count = 0
        self.start_time = datetime.now()
        self.stop_event = Event()
        
        # الحصول على عنوان IP الخاص بنقطة الاتصال تلقائيًا
        self.hotspot_ip = self.detect_hotspot_ip()
        
        if not self.hotspot_ip:
            self.console.print("[red]Error: Could not detect hotspot IP address[/red]")
            sys.exit(1)
            
        self.console.print(f"[green]Detected hotspot IP: {self.hotspot_ip}[/green]")
        
        # إضافة عنوان نقطة الاتصال إلى قائمة الأجهزة
        self.devices[self.hotspot_ip] = {
            'ip': self.hotspot_ip,
            'mac': self.get_mac_address(self.hotspot_ip),
            'hostname': socket.gethostname(),
            'sent_bytes': 0,
            'recv_bytes': 0,
            'protocols': set(),
            'domains': set(),
            'last_activity': datetime.now()
        }
    
    def detect_hotspot_ip(self):
        """اكتشاف عنوان IP الخاص بنقطة الاتصال تلقائيًا"""
        try:
            # الطريقة الأولى: استخدام اتصال نشط
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            
            # إذا كان العنوان ضمن نطاق نقاط الاتصال المعتاد
            if ip.startswith('192.168.') or ip.startswith('10.'):
                return ip
            
            # الطريقة الثانية: افتراضي لنقاط اتصال أندرويد
            return '192.168.43.1'
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Could not detect hotspot IP: {e}[/yellow]")
            return '192.168.43.1'  # العنوان الافتراضي لنقطة اتصال أندرويد
    
    def get_mac_address(self, ip):
        """الحصول على عنوان MAC (محاكاة)"""
        # في الواقع الفعلي تحتاج إلى استخدام ARP أو واجهات أندرويد
        return '00:11:22:33:44:55'  # عنوان وهمي للتوضيح
    
    def is_connected_device(self, ip):
        """التحقق مما إذا كان IP ينتمي إلى جهاز متصل"""
        if ip == self.hotspot_ip:
            return False
            
        # نطاقات IP الخاصة بأجهزة متصلة بنقطة الاتصال
        if self.hotspot_ip.startswith('192.168.'):
            return ip.startswith('192.168.')
        elif self.hotspot_ip.startswith('10.'):
            return ip.startswith('10.')
        
        return False
    
    def resolve_hostname(self, ip):
        """حل اسم المضيف لعنوان IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return ip
    
    def monitor_traffic(self):
        """محاكاة مراقبة حركة الشبكة"""
        while not self.stop_event.is_set():
            try:
                # محاكاة اكتشاف أجهزة جديدة
                if len(self.devices) < 3:  # افتراضي لأغراض العرض
                    fake_ip = f"192.168.{len(self.devices)}.{len(self.devices)+2}"
                    if fake_ip not in self.devices and fake_ip != self.hotspot_ip:
                        self.devices[fake_ip] = {
                            'ip': fake_ip,
                            'mac': self.get_mac_address(fake_ip),
                            'hostname': f"device-{len(self.devices)}",
                            'sent_bytes': 0,
                            'recv_bytes': 0,
                            'protocols': set(),
                            'domains': set(),
                            'last_activity': datetime.now()
                        }
                
                # محاكاة حركة الشبكة
                for ip, data in list(self.devices.items()):
                    if ip != self.hotspot_ip:  # زيادة حركة الأجهزة المتصلة فقط
                        data['sent_bytes'] += 100 + int(time.time() % 100)
                        data['recv_bytes'] += 150 + int(time.time() % 120)
                        data['last_activity'] = datetime.now()
                        data['protocols'].update(['TCP', 'UDP'])
                        
                        # محاكاة زيارات نطاقات
                        if int(time.time()) % 10 == 0:
                            domain = f"example{int(time.time()%5)}.com"
                            data['domains'].add(domain)
                
                self.traffic_count += 1
                time.sleep(1)
                
            except Exception as e:
                self.console.print(f"[yellow]Monitoring error: {e}[/yellow]")
                time.sleep(2)
    
    def generate_report(self):
        """إنشاء تقرير بالحركة المكتشفة"""
        report = {
            "hotspot_ip": self.hotspot_ip,
            "start_time": self.start_time.isoformat(),
            "end_time": datetime.now().isoformat(),
            "total_devices": len(self.devices) - 1,  # نستثني عنوان نقطة الاتصال
            "devices": []
        }
        
        for ip, data in self.devices.items():
            if ip != self.hotspot_ip:  # نستثني نقطة الاتصال من التقرير
                device_report = {
                    "ip_address": ip,
                    "mac_address": data['mac'],
                    "hostname": data.get('hostname', ip),
                    "sent_bytes": data['sent_bytes'],
                    "recv_bytes": data['recv_bytes'],
                    "protocols": list(data['protocols']),
                    "domains": list(data['domains']),
                    "last_activity": data['last_activity'].isoformat()
                }
                report["devices"].append(device_report)
        
        return report
    
    def save_report(self, report):
        """حفظ التقرير إلى ملف"""
        try:
            with open(self.log_file, 'a') as f:
                json.dump(report, f, indent=2)
                f.write("\n")
            self.console.print(f"[green]Report saved to {self.log_file}[/green]")
        except Exception as e:
            self.console.print(f"[red]Error saving report: {e}[/red]")
    
    def create_ui(self):
        """إنشاء واجهة المستخدم"""
        layout = Layout()
        
        layout.split(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3)
        )
        
        layout["header"].update(Panel(f"📶 Hotspot Traffic Monitor - IP: {self.hotspot_ip}", style="bold blue"))
        layout["footer"].update(Panel("Press Ctrl+C to stop monitoring", style="bold yellow"))
        
        return layout
    
    def update_ui(self, layout):
        """تحديث واجهة المستخدم بالبيانات الجديدة"""
        # جدول الأجهزة الرئيسي
        main_table = Table(title=f"Connected Devices ({len(self.devices)-1})", show_header=True, header_style="bold magenta")
        main_table.add_column("IP", style="cyan")
        main_table.add_column("MAC", style="cyan")
        main_table.add_column("Hostname", style="green")
        main_table.add_column("Sent (KB)", justify="right")
        main_table.add_column("Recv (KB)", justify="right")
        main_table.add_column("Protocols")
        main_table.add_column("Last Activity")
        
        for ip, data in self.devices.items():
            if ip != self.hotspot_ip:  # نستثني نقطة الاتصال من العرض
                main_table.add_row(
                    ip,
                    data['mac'],
                    data.get('hostname', ip),
                    f"{data['sent_bytes']/1024:.1f}",
                    f"{data['recv_bytes']/1024:.1f}",
                    ", ".join(data['protocols']),
                    data['last_activity'].strftime("%H:%M:%S")
                )
        
        # لوحة الإحصائيات
        stats_text = Text()
        stats_text.append(f"Hotspot IP: {self.hotspot_ip}\n", style="bold")
        stats_text.append(f"Monitoring duration: {datetime.now() - self.start_time}\n")
        stats_text.append(f"Total devices: {len(self.devices)-1}\n")
        stats_text.append(f"Last update: {datetime.now().strftime('%H:%M:%S')}")
        
        stats_panel = Panel(stats_text, title="Statistics", border_style="green")
        
        # لوحة النطاقات
        domains_panel = Panel("No domain data yet", title="Domains Visited", border_style="blue")
        if len(self.devices) > 1:
            most_active = max((d for ip, d in self.devices.items() if ip != self.hotspot_ip), 
                            key=lambda x: x['sent_bytes'] + x['recv_bytes'])
            if most_active['domains']:
                domains_text = Text("\n".join(sorted(most_active['domains'])))
                domains_panel = Panel(domains_text, title=f"Domains Visited by {most_active.get('hostname', most_active['ip'])}", border_style="blue")
        
        # تحديث التخطيط الرئيسي
        layout["main"].split(
            Layout(main_table, name="devices", ratio=2),
            Layout(stats_panel, name="stats", size=8),
            Layout(domains_panel, name="domains", ratio=1)
        )
        
        return layout
    
    def start_monitoring(self):
        """بدء عملية المراقبة"""
        self.running = True
        
        # بدء خيط مراقبة الحركة
        monitor_thread = Thread(target=self.monitor_traffic)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # إعداد واجهة المستخدم
        layout = self.create_ui()
        
        try:
            with Live(layout, refresh_per_second=4, screen=True) as live:
                while self.running:
                    try:
                        live.update(self.update_ui(layout))
                        time.sleep(0.25)
                    except KeyboardInterrupt:
                        self.running = False
                        self.stop_event.set()
                        break
        except Exception as e:
            self.console.print(f"[red]UI Error: {e}[/red]")
        finally:
            self.running = False
            self.stop_event.set()
            monitor_thread.join(timeout=2)
            
            # حفظ التقرير النهائي
            report = self.generate_report()
            self.save_report(report)
            self.console.print("[green]Monitoring stopped. Report saved.[/green]")

if __name__ == "__main__":
    monitor = HotspotMonitor()
    monitor.start_monitoring()