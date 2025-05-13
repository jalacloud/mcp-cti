# otx-cti MCP Server
An MCP (Model Context Protocol) server for accessing AlienVault Open Threat Exchange (OTX) threat intelligence directly in Claude.

![ORKL + OTX](https://github.com/user-attachments/assets/8e6feb59-3735-4b29-8354-f8caa317fd5c)

## Overview
This server connects to AlienVault's OTX DirectConnect API, allowing the Claude for desktop client to search, retrieve, and analyse cyber threat intelligence data. Use this tool to interact with the OTX API using natural language prompting via Claude. By installing this MCP server, you get access to the most recent threat data, including:

* Threat intelligence pulses
* Indicators of compromise (IOCs)
* Malicious IP addresses, domains, and URLs
* Malware file hashes
* Threat actor information

## Features

* Real-time Threat Intelligence: Access the latest threat data from AlienVault OTX's global community
* Comprehensive IOC Analysis: Check if IPs, domains, URLs, or file hashes are known to be malicious
* Threat Actor Profiling: Retrieve information about known threat actors and their activities
* Cached Results: Optimised performance with local caching of API responses
* Asynchronous API: Built with modern async Python for efficient handling of API requests

## Tools Provided

| Tool Name | Description |
|-----------|-------------|
| `search_pulses` | Search for threat intelligence pulses in OTX |
| `get_recent_pulses` | Get recent threat intelligence pulses |
| `get_pulse_details` | Get detailed information about a specific pulse |
| `get_pulse_indicators` | Get indicators of compromise (IOCs) from a specific pulse |
| `get_indicator_details` | Get detailed information about a specific indicator |
| `check_indicator_malicious` | Check if an indicator is known to be malicious |
| `get_threat_actor` | Get information about a specific threat actor |

## Installation

### Prerequisites

- Python 3.8 or higher
- An AlienVault OTX account and API key ([Sign up here](https://otx.alienvault.com/))
- `uv` package manager (recommended) or `pip`

### Set Up Using UV (Recommended)

1. Clone this repository:
   ```bash
   git clone https://github.com/your-username/otx-mcp-server.git
   cd otx-mcp-server

2. Create a Python environment and install dependencies:
    ```bash
    uv venv
    source .venv/bin/activate  # On Windows: .venv\Scripts\activate
    uv pip install -e

### Set Up Using Pip

1. Clone this repository:
   ```bash
   git clone https://github.com/your-username/otx-mcp-server.git
   cd otx-mcp-server

2. Create a Python environment and install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -e

### Quick install with Claude Desktop
Add the following to your Claude Desktop configuration (claude_desktop_config.json):
```json{
  "mcpServers": {
    "otx": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/otx-mcp-server",
        "run",
        "otx"
      ],
      "env": {
        "OTX_API_KEY": "YOUR_API_KEY_HERE"
      }
    }
  }
}
```

The configuration file is typically located at:

macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
Windows: `%APPDATA%\Claude\claude_desktop_config.json`
Linux: `~/.config/Claude/claude_desktop_config.json`

## Sample Prompts
Here are some example prompts to use with the OTX MCP server:

- "Search for recent threat intelligence related to ransomware attacks on healthcare organisations."
- "Check if the IP address xxx.xx.xx.xx is associated with any known threats."
- "Get information about the Golden Chickens/Venom Spider threat actor and their recent activities."
- "Search OTX for specific industry-related threat intelligence. I am looking for threats targeting Financial Services organisations"
- "Find indicators of compromise related to the CWE-94 vulnerability."
- "Check if the domain malicious-example.com is known to be malicious."
- "Get the latest threat intelligence pulses from the past 3 days."

### Resource Types
The server provides access to several resource types:

* Pulses: otx://pulse/{pulse_id}
* Indicators: otx://indicator/{indicator_type}/{indicator_value}
* Threat Actors: otx://actor/{actor_name}

These resources can be referenced and accessed throughout your conversation with Claude.

### Security Considerations
This tool is designed for legitimate security research and defence purposes. Always:

* *Use responsibly and follow applicable laws and regulations*
* *Maintain proper authorisation for any security testing*
* *Handle threat intelligence data with appropriate operational security controls (OPSEC)*
