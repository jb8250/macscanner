# macscanner.py - macOS Security Scanner Explanation

Your `macscanner.py` is a comprehensive macOS security scanner that performs automated threat analysis using AI. Here's what it does:

## Core Purpose
- Scans your macOS system for potential security threats
- Automatically investigates suspicious processes, startup items, and open network ports
- Uses AI (Llama API) to analyze findings and provide threat verdicts

## Key Components

### DeepInvestigator Class
- Process Investigation: Gathers detailed info including executable paths, network connections, parent processes, CPU/memory usage, file hashes, and code signatures
- Startup Item Analysis: Examines LaunchAgents/Daemons plist files for suspicious configurations like auto-restart or network listeners
- Port Analysis: Evaluates open ports for risk levels based on common attack vectors and exposure

### MacSecurityAnalyzer Class
- System Scanning: Collects running processes, non-Apple startup items, and listening network ports
- Auto-Investigation: Selects high-risk items (network-active processes, resource-intensive apps, all open ports) for deep analysis
- AI Consultation: Sends structured prompts to Llama AI for threat assessment with confidence scores and recommended actions

## Workflow
1. Sets up Llama API client (requires LLAMA_API_KEY)
2. Scans system components (processes, startup items, ports)
3. Auto-selects suspicious items for investigation
4. Performs deep analysis on each item
5. Consults AI for verdicts (SAFE/SUSPICIOUS/MALICIOUS)
6. Displays results in rich console tables with threat summaries
7. Saves detailed JSON report with timestamp

## Output Features
- Beautiful terminal interface using Rich library
- Categorized results: Malicious (red), Suspicious (yellow), Safe (green)
- Progress bars during investigation
- Port exposure analysis
- JSON report file for detailed review

## Requirements
The script requires the following Python libraries:
- `psutil` - for system process and network information
- `llama-api-client` - for AI threat analysis
- `rich` - for beautiful console output (auto-installed if missing)

## Usage
Run the script with:
```bash
python3 macscanner.py
```

Ensure you have set the `LLAMA_API_KEY` environment variable or enter it when prompted.
