#!/usr/bin/env python3
"""
macOS Security Scanner with Auto-Investigation
Automatically investigates suspicious items and consults AI for threat analysis
"""

import os
import subprocess
import json
import psutil
import plistlib
from pathlib import Path
from llama_api_client import LlamaAPIClient
import getpass
import re
from datetime import datetime
import time
import hashlib
import traceback

# Rich library for beautiful output
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    from rich.prompt import Prompt, Confirm
    RICH_AVAILABLE = True
except ImportError:
    print("Installing rich library...")
    subprocess.run(['pip3', 'install', 'rich'], check=True)
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    from rich.prompt import Prompt, Confirm

console = Console()

class DeepInvestigator:
    """Performs deep investigation on suspicious processes and files"""
    
    def __init__(self, llama_client):
        self.client = llama_client
    
    def get_file_hash(self, filepath):
        """Calculate SHA256 hash of a file"""
        try:
            if not os.path.exists(filepath):
                return None
            
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return None
    
    def get_process_full_details(self, pid):
        """Get comprehensive process information"""
        try:
            proc = psutil.Process(pid)
            
            # Get executable path
            try:
                exe_path = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                exe_path = None
            
            # Get all open files
            open_files = []
            try:
                for f in proc.open_files()[:10]:
                    open_files.append(str(f.path))
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                pass
            
            # Get network connections with details
            connections = []
            try:
                for conn in proc.net_connections():
                    conn_info = {
                        'local': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'remote': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status
                    }
                    connections.append(conn_info)
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                pass
            
            # Get parent process chain
            parent_chain = []
            try:
                parent = proc.parent()
                depth = 0
                while parent and depth < 3:
                    try:
                        parent_chain.append({
                            'pid': parent.pid,
                            'name': parent.name()
                        })
                        parent = parent.parent()
                        depth += 1
                    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                        break # Stop if parent process is inaccessible
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                pass
            
            # Safely get process attributes
            try:
                name = proc.name()
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                name = "Unavailable"
            
            try:
                cmdline = ' '.join(proc.cmdline()) if proc.cmdline() else ''
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                cmdline = "Unavailable"
            
            try:
                user = proc.username()
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                user = "Unavailable"
            
            try:
                cpu_percent = proc.cpu_percent(interval=0.1)
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                cpu_percent = 0.0
            
            try:
                memory_percent = proc.memory_percent()
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                memory_percent = 0.0
            
            details = {
                'pid': pid,
                'name': name,
                'exe': exe_path,
                'cmdline': cmdline,
                'user': user,
                'cpu_percent': cpu_percent,
                'memory_percent': memory_percent,
                'connections': connections,
                'parent_chain': parent_chain,
                'num_connections': len(connections)
            }
            
            # Calculate file hash if executable exists
            if exe_path:
                details['file_hash'] = self.get_file_hash(exe_path)
                
                # Check if it's signed (macOS specific)
                try:
                    result = subprocess.run(
                        ['codesign', '-dv', exe_path],
                        capture_output=True, text=True, timeout=5
                    )
                    details['code_signed'] = result.returncode == 0
                except Exception:
                    details['code_signed'] = None
            
            return details
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            return {'error': str(e), 'pid': pid}
        except Exception as e:
            return {'error': f"Unexpected error: {e}", 'pid': pid}
    
    def investigate_startup_item(self, item):
        """Deep investigation of a startup item"""
        investigation = {
            'item': item,
            'findings': []
        }
        
        # Check if program file exists and get details
        program = item.get('program', '')
        if program and program != 'Unknown':
            program_path = Path(program)
            
            if program_path.exists():
                investigation['program_exists'] = True
                investigation['file_hash'] = self.get_file_hash(str(program_path))
                
                # Check code signature
                try:
                    result = subprocess.run(
                        ['codesign', '-dv', str(program_path)],
                        capture_output=True, text=True, timeout=5
                    )
                    investigation['code_signed'] = result.returncode == 0
                except Exception:
                    investigation['code_signed'] = None
            else:
                investigation['program_exists'] = False
                investigation['findings'].append("Program file does not exist")
        
        # Read plist file for detailed analysis
        plist_path = item.get('path', '')
        if plist_path and plist_path != 'Login Item':
            try:
                with open(plist_path, 'rb') as f:
                    plist_data = plistlib.load(f)
                    
                    # Check for suspicious configurations
                    if plist_data.get('KeepAlive'):
                        investigation['findings'].append("Configured to restart if killed")
                    
                    if plist_data.get('RunAtLoad'):
                        investigation['findings'].append("Runs automatically at boot")
                    
                    # Check for network listeners
                    if 'Sockets' in plist_data:
                        investigation['findings'].append(f"Opens network sockets")
                    
                    investigation['plist_config'] = {
                        k: v for k, v in plist_data.items() 
                        if k in ['Label', 'Program', 'ProgramArguments', 'RunAtLoad', 'KeepAlive']
                    }
            except Exception as e:
                investigation['findings'].append(f"Error reading plist: {e}")
        
        return investigation
    def investigate_port(self, port_info):
        """Investigate an open port"""
        investigation = {
            'port': port_info,
            'findings': [],
            'risk_level': 'low'
        }
        
        port = port_info['port']
        
        # Check for commonly attacked ports
        high_risk_ports = [21, 22, 23, 3389, 5900, 445, 139]  # FTP, SSH, Telnet, RDP, VNC, SMB
        medium_risk_ports = [80, 443, 8080, 3306, 5432, 27017]  # Web servers, databases
        
        if port in high_risk_ports:
            investigation['risk_level'] = 'high'
            investigation['findings'].append(f"Port {port} is commonly targeted by attackers")
        elif port in medium_risk_ports:
            investigation['risk_level'] = 'medium'
            investigation['findings'].append(f"Port {port} is a common service port")
        
        # Check if bound to all interfaces (0.0.0.0)
        if port_info['address'] == '0.0.0.0':
            investigation['findings'].append("Exposed to all network interfaces (public access)")
        elif port_info['address'] == '127.0.0.1':
            investigation['findings'].append("Only accessible locally (safe)")
        
        return investigation

    def consult_ai_for_port(self, port_info, investigation):
        """Ask AI to analyze an open port"""
        prompt = f"""Analyze this open network port for security risks.

Port: {port_info['port']}
Address: {port_info['address']}
Process: {port_info.get('process', 'Unknown')}
User: {port_info.get('user', 'Unknown')}
Command: {port_info.get('cmdline', 'Unknown')}
Risk Level: {investigation['risk_level']}
Findings: {', '.join(investigation['findings'])}

Common port info:
- 22: SSH
- 80/443: HTTP/HTTPS
- 3306: MySQL
- 5432: PostgreSQL
- 27017: MongoDB

Respond in EXACT format:
VERDICT: [SAFE/SUSPICIOUS/MALICIOUS]
CONFIDENCE: [0-100]
THREAT_TYPE: [legitimate/exposed_service/backdoor/etc]
REASONING: [one sentence about why this port is open and if it's concerning]
ACTION: [WHITELIST/MONITOR/INVESTIGATE/CLOSE]
"""
        
        try:
            response = self.client.chat.completions.create(
                model="Llama-4-Maverick-17B-128E-Instruct-FP8",
                messages=[{"role": "user", "content": prompt}],
            )
            
            # Use same text extraction as before
            text = None
            if hasattr(response, 'completion_message'):
                if hasattr(response.completion_message, 'content'):
                    content = response.completion_message.content
                    if hasattr(content, 'text'):
                        text = content.text
            
            if not text:
                response_str = str(response)
                if "text='" in response_str:
                    match = re.search(r"text='(.+?)', type=", response_str, re.DOTALL)
                    if match:
                        text = match.group(1).replace("\\n", "\n")
            
            if text:
                return self.parse_ai_verdict(text)
            
            return {'error': 'Could not parse response'}
            
        except Exception as e:
            return {'error': str(e)}
    
    def consult_ai_for_item(self, investigation, item_type="process"):
        """Consult Llama AI for specific item analysis"""
        
        if item_type == "process":
            details = investigation
            
            # Build connection summary
            conn_summary = "No network activity"
            if details.get('connections'):
                unique_remotes = set()
                for conn in details['connections'][:10]:
                    if conn.get('remote'):
                        unique_remotes.add(conn['remote'])
                if unique_remotes:
                    conn_summary = f"{len(unique_remotes)} unique destinations"
            
            prompt = f"""You are a cybersecurity expert analyzing a macOS process.

Process: {details.get('name')}
User: {details.get('user')}
Executable: {details.get('exe', 'Unknown')[:80]}
Command: {details.get('cmdline', '')[:150]}
Parent: {details.get('parent_chain', [{}])[0].get('name', 'Unknown') if details.get('parent_chain') else 'Unknown'}
Network: {conn_summary}
Code Signed: {details.get('code_signed', 'Unknown')}
CPU: {details.get('cpu_percent', 0):.1f}% | Memory: {details.get('memory_percent', 0):.1f}%

Provide analysis in this EXACT format:

VERDICT: [SAFE or SUSPICIOUS or MALICIOUS]
CONFIDENCE: [number from 0-100]
THREAT_TYPE: [legitimate/adware/spyware/malware/cryptominer/unknown]
REASONING: [One clear sentence explaining your verdict]
ACTION: [WHITELIST or MONITOR or INVESTIGATE or TERMINATE]
"""
        else:  # startup item
            item = investigation.get('item', {})
            prompt = f"""You are a cybersecurity expert analyzing a macOS startup item.

Label: {item.get('label')}
Type: {item.get('type')}
Program: {item.get('program', 'Unknown')[:80]}
Enabled: {item.get('enabled')}
Auto-run: {item.get('run_at_load')}

Investigation:
- Program exists: {investigation.get('program_exists', 'Unknown')}
- Code signed: {investigation.get('code_signed', 'Unknown')}
- Findings: {', '.join(investigation.get('findings', ['None']))}

Provide analysis in this EXACT format:

VERDICT: [SAFE or SUSPICIOUS or MALICIOUS]
CONFIDENCE: [number from 0-100]
THREAT_TYPE: [legitimate/persistence/adware/spyware/malware/unknown]
REASONING: [One clear sentence explaining your verdict]
ACTION: [WHITELIST or MONITOR or DISABLE or REMOVE]
"""
        
        try:
            response = self.client.chat.completions.create(
                model="Llama-4-Maverick-17B-128E-Instruct-FP8",
                messages=[
                    {"role": "user", "content": prompt},
                ],
            )
            
            # Extract text from response
            text = None
            if hasattr(response, 'completion_message'):
                if hasattr(response.completion_message, 'content'):
                    content = response.completion_message.content
                    if hasattr(content, 'text'):
                        text = content.text
            
            if not text:
                response_str = str(response)
                if "text='" in response_str:
                    match = re.search(r"text='(.+?)', type=", response_str, re.DOTALL)
                    if match:
                        text = match.group(1).replace("\\n", "\n")
            
            if text:
                return self.parse_ai_verdict(text)
            
            return {'error': 'Could not parse response'}
            
        except Exception as e:
            return {'error': str(e)}
    
    def parse_ai_verdict(self, text):
        """Parse AI response into structured verdict"""
        verdict = {
            'verdict': 'UNKNOWN',
            'confidence': 0,
            'threat_type': 'unknown',
            'reasoning': '',
            'action': 'INVESTIGATE',
            'raw_response': text
        }
        
        # Extract verdict
        verdict_match = re.search(r'VERDICT:\s*```math\n?([^```\n]+)', text, re.IGNORECASE)
        if verdict_match:
            verdict['verdict'] = verdict_match.group(1).strip().upper()
        
        # Extract confidence
        conf_match = re.search(r'CONFIDENCE:\s*```math\n?(\d+)', text, re.IGNORECASE)
        if conf_match:
            verdict['confidence'] = int(conf_match.group(1))
        
        # Extract threat type
        threat_match = re.search(r'THREAT_TYPE:\s*```math\n?([^```\n]+)', text, re.IGNORECASE)
        if threat_match:
            verdict['threat_type'] = threat_match.group(1).strip()
        
        # Extract reasoning
        reason_match = re.search(r'REASONING:\s*```math\n?([^\n]+)', text, re.IGNORECASE)
        if reason_match:
            verdict['reasoning'] = reason_match.group(1).strip()[:300]
        
        # Extract action
        action_match = re.search(r'ACTION:\s*```math\n?([^```\n]+)', text, re.IGNORECASE)
        if action_match:
            verdict['action'] = action_match.group(1).strip().upper()
        
        return verdict

class MacSecurityAnalyzer:
    def __init__(self):
        self.client = None
        self.investigator = None
    
    def setup_llama_client(self):
        """Setup Llama API client"""
        api_key = os.environ.get("LLAMA_API_KEY")
        
        if not api_key:
            console.print("\n[yellow]⚠️  LLAMA_API_KEY not found[/yellow]")
            choice = console.input("\n[bold]Enter API key now? (y/n):[/bold] ").lower()
            if choice == 'y':
                api_key = getpass.getpass("Enter your Llama API key: ")
                os.environ["LLAMA_API_KEY"] = api_key
                console.print("[green]✅ API key set[/green]\n")
            else:
                console.print("[red]❌ Cannot proceed without API key[/red]")
                exit(1)
        else:
            console.print("[green]✅ LLAMA_API_KEY found[/green]\n")
        
        self.client = LlamaAPIClient(
            api_key=api_key,
            base_url="https://api.llama.com/v1/",
        )
        
        self.investigator = DeepInvestigator(self.client)
    
    def get_running_processes(self):
        """Get list of running processes"""
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
            try:
                pinfo = proc.info # This is where name, username, cmdline are initially populated
                
                # Get network connections
                connections = []
                try:
                    for conn in proc.net_connections(kind='inet'):
                        connections.append({
                            'remote': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                            'status': conn.status
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass # Connections might not be accessible, continue without them
                
                # Get CPU and memory
                try:
                    pinfo['cpu_percent'] = proc.cpu_percent(interval=0)
                    pinfo['memory_percent'] = proc.memory_percent()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pinfo['cpu_percent'] = 0
                    pinfo['memory_percent'] = 0
                except Exception:
                    pinfo['cpu_percent'] = 0
                    pinfo['memory_percent'] = 0
                
                pinfo['connections'] = connections
                pinfo['cmdline'] = ' '.join(pinfo['cmdline']) if pinfo['cmdline'] else ''
                
                processes.append(pinfo)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Process no longer exists or access denied - skip it
                continue
            except Exception as e:
                # Catch any other unexpected errors for this process
                console.log(f"Unexpected error processing PID {proc.pid}: {e}")
                continue
        
        return sorted(processes, key=lambda x: x.get('memory_percent', 0), reverse=True)
    
    def get_startup_items(self):
        """Get startup items"""
        startup_items = []
        
        launch_paths = [
            (Path.home() / "Library/LaunchAgents", "User LaunchAgent"),
            (Path("/Library/LaunchAgents"), "Global LaunchAgent"),
            (Path("/Library/LaunchDaemons"), "System LaunchDaemon"),
        ]
        
        for path, item_type in launch_paths:
            if not path.exists():
                continue
                
            for plist_file in path.glob("*.plist"):
                try:
                    with open(plist_file, 'rb') as f:
                        plist_data = plistlib.load(f)
                    
                    label = plist_data.get('Label', plist_file.stem)
                    program = plist_data.get('Program', '')
                    if not program and 'ProgramArguments' in plist_data:
                        program = plist_data['ProgramArguments'][0] if plist_data['ProgramArguments'] else ''
                    
                    # Skip Apple system items
                    if label.startswith('com.apple'):
                        continue
                    
                    startup_items.append({
                        'path': str(plist_file),
                        'type': item_type,
                        'label': label,
                        'program': program,
                        'enabled': not plist_data.get('Disabled', False),
                        'run_at_load': plist_data.get('RunAtLoad', False),
                    })
                    
                except Exception:
                    pass
        
        return startup_items
    def get_open_ports(self):
        """Scan for open ports on localhost"""
        open_ports = []
        
        # Get all listening connections
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    port_info = {
                        'port': conn.laddr.port,
                        'address': conn.laddr.ip,
                        'pid': conn.pid,
                        'process': None
                    }
                    
                    # Get process info
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            port_info['process'] = proc.name()
                            port_info['cmdline'] = ' '.join(proc.cmdline())[:100]
                            port_info['user'] = proc.username()
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                            # Process no longer exists or access denied
                            port_info['process'] = "Unavailable"
                            port_info['cmdline'] = "Unavailable"
                            port_info['user'] = "Unavailable"
                        except Exception as e:
                            # Catch any other unexpected errors
                            port_info['process'] = f"Error: {e}"
                            port_info['cmdline'] = f"Error: {e}"
                            port_info['user'] = f"Error: {e}"
                    
                    open_ports.append(port_info)
        except (psutil.AccessDenied, PermissionError) as e:
            console.print(f"[yellow]Warning: Could not retrieve all network connections due to permission issues: {e}[/yellow]")
        except Exception as e:
            console.print(f"[red]Error retrieving network connections: {e}[/red]")
        
        # Sort by port number
        return sorted(open_ports, key=lambda x: x['port'])
    
    def auto_investigate(self, processes, startup_items):
        """Automatically investigate interesting items"""
        
        console.print("\n[bold cyan]🔍 AUTO-INVESTIGATION MODE[/bold cyan]\n")
        
        open_ports = self.get_open_ports()
        
        # Select items to investigate
        investigate_procs = []
        investigate_items = []
        
        # Investigate top network-active processes
        network_procs = sorted(
            [p for p in processes if len(p.get('connections', [])) > 2],
            key=lambda x: len(x.get('connections', [])),
            reverse=True
        )[:5]  # Top 5 network-active
        
        investigate_procs.extend(network_procs)
        
        # Investigate high CPU/memory processes
        resource_procs = [p for p in processes if p.get('cpu_percent', 0) > 30 or p.get('memory_percent', 0) > 10][:3]
        investigate_procs.extend(resource_procs)
        
        # Investigate non-Apple startup items (sample)
        investigate_items = startup_items[:10]  # First 10 non-Apple items
        
        # Remove duplicates
        investigate_procs = list({p['pid']: p for p in investigate_procs}.values())
        
        investigate_ports = open_ports  # Investigate all open ports
        
        total = len(investigate_procs) + len(investigate_items) + len(investigate_ports)
        
        if total == 0:
            console.print("[yellow]No items selected for investigation[/yellow]")
            return []
        
        console.print(f"[cyan]Investigating {len(investigate_procs)} processes, {len(investigate_items)} startup items, and {len(investigate_ports)} ports...[/cyan]\n")
        
        results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[cyan]{task.completed}/{task.total}"),
            console=console
        ) as progress:
            
            task = progress.add_task("[cyan]Investigating...", total=total)
            
            # Investigate processes
            for proc in investigate_procs:
                try:
                    progress.update(task, description=f"[cyan]Process: {proc['name'][:25]}...")
                    
                    details = self.investigator.get_process_full_details(proc['pid'])
                    
                    if 'error' not in details:
                        verdict = self.investigator.consult_ai_for_item(details, "process")
                        
                        if verdict and 'error' not in verdict:
                            results.append({
                                'type': 'process',
                                'name': proc['name'],
                                'pid': proc['pid'],
                                'details': details,
                                'verdict': verdict
                            })
                    
                    progress.update(task, advance=1)
                    time.sleep(0.3)  # Rate limiting
                except Exception as e:
                    # Process no longer exists or access denied - skip it
                    progress.update(task, advance=1)
                    continue
            
            # Investigate startup items
            for item in investigate_items:
                try:
                    progress.update(task, description=f"[cyan]Startup: {item['label'][:25]}...")
                    
                    investigation = self.investigator.investigate_startup_item(item)
                    verdict = self.investigator.consult_ai_for_item(investigation, "startup")
                    
                    if verdict and 'error' not in verdict:
                        results.append({
                            'type': 'startup',
                            'name': item['label'],
                            'item': item,
                            'investigation': investigation,
                            'verdict': verdict
                        })
                    
                    progress.update(task, advance=1)
                    time.sleep(0.3)  # Rate limiting
                except Exception as e:
                    progress.update(task, advance=1)
                    continue
            
            # Investigate ports
            for port_info in investigate_ports:
                try:
                    progress.update(task, description=f"[cyan]Port: {port_info['port']}...")
                    
                    investigation = self.investigator.investigate_port(port_info)
                    verdict = self.investigator.consult_ai_for_port(port_info, investigation)
                    
                    if verdict and 'error' not in verdict:
                        results.append({
                            'type': 'port',
                            'name': f"Port {port_info['port']}",
                            'port': port_info['port'],
                            'process': port_info.get('process', 'Unknown'),
                            'verdict': verdict
                        })
                    
                    progress.update(task, advance=1)
                    time.sleep(0.3)
                except Exception as e:
                    progress.update(task, advance=1)
                    continue
        
        return results
    
    def display_investigation_results(self, results):
        """Display investigation results"""
        
        if not results:
            console.print("\n[yellow]No investigation results[/yellow]")
            return
        
        console.print("\n" + "=" * 70)
        console.print("[bold cyan]🤖 INVESTIGATION RESULTS[/bold cyan]")
        console.print("=" * 70 + "\n")
        
        # Group by verdict
        malicious = [r for r in results if 'MALICIOUS' in r['verdict'].get('verdict', '')]
        suspicious = [r for r in results if 'SUSPICIOUS' in r['verdict'].get('verdict', '')]
        safe = [r for r in results if 'SAFE' in r['verdict'].get('verdict', '')]
        
        # Display malicious
        if malicious:
            table = Table(title="🔴 MALICIOUS ITEMS", box=box.ROUNDED, show_lines=True)
            table.add_column("Item", style="red", width=25)
            table.add_column("Type", style="magenta", width=10)
            table.add_column("Threat", style="yellow", width=15)
            table.add_column("Confidence", justify="center", style="cyan", width=10)
            table.add_column("Reasoning", style="white", no_wrap=False)
            
            for r in malicious:
                v = r['verdict']
                table.add_row(
                    r['name'][:25],
                    r['type'],
                    v.get('threat_type', 'Unknown')[:15],
                    f"{v.get('confidence', 0)}%",
                    v.get('reasoning', '')[:100]
                )
            
            console.print(table)
            console.print()
        
        # Display suspicious
        if suspicious:
            table = Table(title="🟡 SUSPICIOUS ITEMS", box=box.ROUNDED, show_lines=True)
            table.add_column("Item", style="yellow", width=25)
            table.add_column("Type", style="magenta", width=10)
            table.add_column("Threat", style="cyan", width=15)
            table.add_column("Confidence", justify="center", style="cyan", width=10)
            table.add_column("Reasoning", style="white", no_wrap=False)
            
            for r in suspicious:
                v = r['verdict']
                table.add_row(
                    r['name'][:25],
                    r['type'],
                    v.get('threat_type', 'Unknown')[:15],
                    f"{v.get('confidence', 0)}%",
                    v.get('reasoning', '')[:100]
                )
            
            console.print(table)
            console.print()
        
        # Show port summary
        ports = [r for r in results if r['type'] == 'port']
        if ports:
            console.print(f"\n[bold cyan]🔌 OPEN PORTS ANALYZED: {len(ports)}[/bold cyan]")
            for p in ports:
                status = "🔴" if 'MALICIOUS' in p['verdict']['verdict'] else "🟡" if 'SUSPICIOUS' in p['verdict']['verdict'] else "🟢"
                console.print(f"  {status} Port {p['port']} - {p.get('process', 'Unknown')} - {p['verdict'].get('reasoning', '')[:60]}")
            console.print()
        
        # Display safe (collapsed)
        if safe:
            console.print(f"[bold green]✅ SAFE ITEMS ({len(safe)} items)[/bold green]")
            for r in safe[:5]:  # Show first 5
                console.print(f"  • {r['name'][:40]}")
            if len(safe) > 5:
                console.print(f"  ... and {len(safe) - 5} more")
            console.print()
        
        # Summary
        console.print(f"\n[bold]Summary:[/bold]")
        console.print(f"  🔴 Malicious: [red]{len(malicious)}[/red]")
        console.print(f"  🟡 Suspicious: [yellow]{len(suspicious)}[/yellow]")
        console.print(f"  🟢 Safe: [green]{len(safe)}[/green]")
        console.print(f"  📊 Total: [cyan]{len(results)}[/cyan]")
    
    def generate_report(self):
        """Generate security report"""
        
        console.print(Panel.fit(
            "🛡️  [bold cyan]macOS Security Scanner[/bold cyan] 🛡️\n"
            "AI-Powered Deep Investigation",
            border_style="cyan"
        ))
        
        self.setup_llama_client()
        
        console.print("\n[cyan]Scanning system...[/cyan]")
        processes = self.get_running_processes()
        startup_items = self.get_startup_items()
        
        console.print(f"[green]✓[/green] Found {len(processes)} processes")
        console.print(f"[green]✓[/green] Found {len(startup_items)} non-Apple startup items")
        
        open_ports = self.get_open_ports()
        console.print(f"[green]✓[/green] {len(open_ports)} open ports")
        
        # Auto-investigate
        results = self.auto_investigate(processes, startup_items)
        
        # Display results
        self.display_investigation_results(results)
        
        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f'security_investigation_{timestamp}.json'
        
        with open(report_file, 'w') as f:
            json.dump({
                'timestamp': timestamp,
                'investigated': len(results),
                'results': results
            }, f, indent=2, default=str)
        
        console.print(f"\n[green]✅ Report saved:[/green] [cyan]{report_file}[/cyan]")
        
        return results, report_file

def main():
    try:
        analyzer = MacSecurityAnalyzer()
        results, report_file = analyzer.generate_report()
        
        malicious_count = len([r for r in results if 'MALICIOUS' in r['verdict'].get('verdict', '')])
        
        console.print("\n" + "=" * 70)
        
        if malicious_count > 0:
            console.print("[bold red]⚠️  ALERT: Potential threats detected![/bold red]")
        else:
            console.print("[bold green]✅ No immediate threats detected[/bold green]")
        
        console.print(f"\n[dim]Full details in {report_file}[/dim]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Error: {str(e)}[/red]")
        traceback.print_exc() # Print full traceback for debugging

if __name__ == "__main__":
    try:
        import psutil
        from llama_api_client import LlamaAPIClient
    except ImportError:
        console.print("[red]Missing packages. Install: pip3 install psutil llama-api-client rich[/red]")
        exit(1)
    
    main()