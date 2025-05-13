import asyncio
import os
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union, Any

from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server
from pydantic import AnyUrl
import mcp.types as types
import mcp.server.stdio
import httpx

from OTXv2 import OTXv2, IndicatorTypes

# AlienVault OTX API Base Configuration
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

# Initialise the MCP server
server = Server("alienvault-otx")

# Cache for pulses, indicators and threat actors
cache = {
    "pulses": {},        # {id: details}
    "indicators": {},    # {type+value: details}
    "threat_actors": {}  # {name: details}
}

# Helper function to get OTX API key from environment
def get_api_key():
    api_key = os.environ.get("OTX_API_KEY")
    if not api_key:
        raise ValueError("OTX_API_KEY environment variable is not set")
    return api_key

# Indicator type mapping
indicator_type_map = {
    "IPv4": IndicatorTypes.IPv4,
    "IPv6": IndicatorTypes.IPv6,
    "domain": IndicatorTypes.DOMAIN,
    "hostname": IndicatorTypes.HOSTNAME,
    "URL": IndicatorTypes.URL,
    "FileHash-MD5": IndicatorTypes.FILE_HASH_MD5,
    "FileHash-SHA1": IndicatorTypes.FILE_HASH_SHA1,
    "FileHash-SHA256": IndicatorTypes.FILE_HASH_SHA256,
    # Add more mappings as needed (future additions)
}

@server.list_resources()
async def handle_list_resources() -> list[types.Resource]:
    """
    List all available resources, including pulses, indicators, and threat actors.
    """
    resources = []

    # Add pulses
    resources.extend([
        types.Resource(
            uri=AnyUrl(f"otx://pulse/{pulse_id}"),
            name=f"Pulse: {details.get('name', 'Unknown')}",
            description=f"Threat intelligence pulse {details.get('name', 'Unknown')}",
            mimeType="application/json",
        )
        for pulse_id, details in cache["pulses"].items()
    ])

    # Add indicators
    resources.extend([
        types.Resource(
            uri=AnyUrl(f"otx://indicator/{indicator_type}/{indicator_value}"),
            name=f"Indicator: {indicator_value} ({indicator_type})",
            description=f"Threat indicator of type {indicator_type}",
            mimeType="application/json",
        )
        for indicator_key, details in cache["indicators"].items()
        for indicator_type, indicator_value in [indicator_key.split(":", 1)]
    ])

    # Add threat actors
    resources.extend([
        types.Resource(
            uri=AnyUrl(f"otx://actor/{actor_name}"),
            name=f"Threat Actor: {actor_name}",
            description=f"Threat actor known as {actor_name}",
            mimeType="application/json",
        )
        for actor_name, details in cache["threat_actors"].items()
    ])

    return resources


@server.read_resource()
async def handle_read_resource(uri: AnyUrl) -> str:
    """
    Read a specific resource's content by its URI.
    """
    if uri.scheme != "otx":
        raise ValueError(f"Unsupported URI scheme: {uri.scheme}")

    path_parts = uri.path.strip("/").split("/")
    resource_type, resource_id = path_parts[0], "/".join(path_parts[1:])

    if resource_type == "pulse":
        return json.dumps(cache["pulses"].get(resource_id, {}), indent=2)
    elif resource_type == "indicator":
        indicator_type, indicator_value = resource_id.split("/", 1)
        cache_key = f"{indicator_type}:{indicator_value}"
        return json.dumps(cache["indicators"].get(cache_key, {}), indent=2)
    elif resource_type == "actor":
        return json.dumps(cache["threat_actors"].get(resource_id, {}), indent=2)
    else:
        raise ValueError(f"Unknown resource type: {resource_type}")


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    """
    List tools to interact with AlienVault OTX API.
    """
    return [
        types.Tool(
            name="search_pulses",
            description="Search for threat intelligence pulses in OTX.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "The search query string"},
                    "limit": {"type": "integer", "description": "Maximum number of results to return (default: 10)"}
                },
                "required": ["query"]
            },
        ),
        types.Tool(
            name="get_recent_pulses",
            description="Get recent threat intelligence pulses from OTX.",
            inputSchema={
                "type": "object",
                "properties": {
                    "days": {"type": "integer", "description": "Number of days to look back (default: 7)"},
                    "limit": {"type": "integer", "description": "Maximum number of results to return (default: 10)"}
                },
                "required": []
            },
        ),
        types.Tool(
            name="get_pulse_details",
            description="Get detailed information about a specific pulse.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pulse_id": {"type": "string", "description": "The ID of the pulse to retrieve"}
                },
                "required": ["pulse_id"]
            },
        ),
        types.Tool(
            name="get_pulse_indicators",
            description="Get indicators of compromise (IOCs) from a specific pulse.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pulse_id": {"type": "string", "description": "The ID of the pulse to retrieve indicators from"}
                },
                "required": ["pulse_id"]
            },
        ),
        types.Tool(
            name="get_indicator_details",
            description="Get detailed information about a specific indicator.",
            inputSchema={
                "type": "object",
                "properties": {
                    "indicator_type": {"type": "string", "description": "Type of indicator (IPv4, domain, hostname, URL, FileHash-MD5, etc.)"},
                    "indicator": {"type": "string", "description": "The indicator value to look up"},
                    "section": {"type": "string", "description": "The section of details to retrieve (general, geo, malware, url_list, etc.)"}
                },
                "required": ["indicator_type", "indicator"]
            },
        ),
        types.Tool(
            name="check_indicator_malicious",
            description="Check if an indicator (IP, domain, URL, file hash) is known to be malicious.",
            inputSchema={
                "type": "object",
                "properties": {
                    "indicator_type": {"type": "string", "description": "Type of indicator (IPv4, domain, hostname, URL, FileHash-MD5, etc.)"},
                    "indicator": {"type": "string", "description": "The indicator value to check"}
                },
                "required": ["indicator_type", "indicator"]
            },
        ),
        types.Tool(
            name="get_threat_actor",
            description="Get information about a specific threat actor.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "The name of the threat actor to look up"}
                },
                "required": ["name"]
            },
        ),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict[str, Any] | None) -> list[types.TextContent]:
    """
    Handle tool execution requests for interacting with the AlienVault OTX API.
    """
    if arguments is None:
        arguments = {}
    
    api_key = get_api_key()
    
    async with httpx.AsyncClient() as client:
        # Add the API key to all requests
        headers = {"X-OTX-API-KEY": api_key}
        
        try:
            if name == "search_pulses":
                query = arguments.get("query")
                limit = arguments.get("limit", 10)
                
                response = await client.get(
                    f"{OTX_BASE_URL}/search/pulses",
                    params={"q": query, "limit": limit},
                    headers=headers
                )
                
                if response.status_code == 200:
                    results = response.json()
                    pulses = results.get("results", [])
                    
                    for pulse in pulses:
                        pulse_id = pulse.get("id")
                        if pulse_id:
                            cache["pulses"][pulse_id] = pulse
                    
                    result_text = "\n".join([
                        f"ID: {pulse.get('id', 'Unknown')}, Name: {pulse.get('name', 'Unknown')}, "
                        f"Created: {pulse.get('created', 'Unknown')}"
                        for pulse in pulses
                    ])
                    
                    return [types.TextContent(type="text", text=result_text)]
                
                return [types.TextContent(type="text", text=f"Error: {response.status_code} - {response.text}")]
            
            elif name == "get_recent_pulses":
                days = arguments.get("days", 7)
                limit = arguments.get("limit", 10)
                
                # Calculate date for modified_since
                modified_since = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
                
                response = await client.get(
                    f"{OTX_BASE_URL}/pulses/subscribed",
                    params={"modified_since": modified_since, "limit": limit},
                    headers=headers
                )
                
                if response.status_code == 200:
                    results = response.json()
                    pulses = results.get("results", [])
                    
                    for pulse in pulses:
                        pulse_id = pulse.get("id")
                        if pulse_id:
                            cache["pulses"][pulse_id] = pulse
                    
                    result_text = "\n".join([
                        f"ID: {pulse.get('id', 'Unknown')}, Name: {pulse.get('name', 'Unknown')}, "
                        f"Modified: {pulse.get('modified', 'Unknown')}"
                        for pulse in pulses
                    ])
                    
                    return [types.TextContent(type="text", text=result_text)]
                
                return [types.TextContent(type="text", text=f"Error: {response.status_code} - {response.text}")]
            
            elif name == "get_pulse_details":
                pulse_id = arguments.get("pulse_id")
                if not pulse_id:
                    raise ValueError("pulse_id is required")
                
                response = await client.get(
                    f"{OTX_BASE_URL}/pulses/{pulse_id}",
                    headers=headers
                )
                
                if response.status_code == 200:
                    pulse = response.json()
                    cache["pulses"][pulse_id] = pulse
                    return [types.TextContent(type="text", text=json.dumps(pulse, indent=2))]
                
                return [types.TextContent(type="text", text=f"Error: {response.status_code} - {response.text}")]
            
            elif name == "get_pulse_indicators":
                pulse_id = arguments.get("pulse_id")
                if not pulse_id:
                    raise ValueError("pulse_id is required")
                
                response = await client.get(
                    f"{OTX_BASE_URL}/pulses/{pulse_id}/indicators",
                    headers=headers
                )
                
                if response.status_code == 200:
                    indicators = response.json()
                    
                    # Cache indicators
                    for indicator in indicators:
                        indicator_type = indicator.get("type")
                        indicator_value = indicator.get("indicator")
                        if indicator_type and indicator_value:
                            cache_key = f"{indicator_type}:{indicator_value}"
                            cache["indicators"][cache_key] = indicator
                    
                    result_text = "\n".join([
                        f"Type: {indicator.get('type', 'Unknown')}, "
                        f"Indicator: {indicator.get('indicator', 'Unknown')}, "
                        f"Created: {indicator.get('created', 'Unknown')}"
                        for indicator in indicators
                    ])
                    
                    return [types.TextContent(type="text", text=result_text)]
                
                return [types.TextContent(type="text", text=f"Error: {response.status_code} - {response.text}")]
            
            elif name == "get_indicator_details":
                indicator_type = arguments.get("indicator_type")
                indicator = arguments.get("indicator")
                section = arguments.get("section", "general")
                
                if not indicator_type or not indicator:
                    raise ValueError("indicator_type and indicator are required")
                
                ind_type = indicator_type_map.get(indicator_type, indicator_type)
                
                endpoint = f"{OTX_BASE_URL}/indicators/{ind_type}/{indicator}/{section}"
                response = await client.get(endpoint, headers=headers)
                
                if response.status_code == 200:
                    details = response.json()
                    cache_key = f"{indicator_type}:{indicator}"
                    
                    # Store only general details in cache
                    if section == "general":
                        cache["indicators"][cache_key] = details
                    
                    return [types.TextContent(type="text", text=json.dumps(details, indent=2))]
                
                return [types.TextContent(type="text", text=f"Error: {response.status_code} - {response.text}")]
            
            elif name == "check_indicator_malicious":
                indicator_type = arguments.get("indicator_type")
                indicator = arguments.get("indicator")
                
                if not indicator_type or not indicator:
                    raise ValueError("indicator_type and indicator are required")
                
                ind_type = indicator_type_map.get(indicator_type, indicator_type)
                
                response = await client.get(
                    f"{OTX_BASE_URL}/indicators/{ind_type}/{indicator}/general",
                    headers=headers
                )
                
                if response.status_code == 200:
                    details = response.json()
                    
                    # Store in cache
                    cache_key = f"{indicator_type}:{indicator}"
                    cache["indicators"][cache_key] = details
                    
                    # Check if the indicator is in any pulses
                    is_malicious = False
                    malicious_pulses = []
                    
                    if "pulse_info" in details and "pulses" in details["pulse_info"]:
                        for pulse in details["pulse_info"]["pulses"]:
                            malicious_pulses.append({
                                "name": pulse.get("name", ""),
                                "id": pulse.get("id", ""),
                                "tlp": pulse.get("TLP", ""),
                                "tags": pulse.get("tags", []),
                                "adversary": pulse.get("adversary", ""),
                            })
                        
                        is_malicious = len(malicious_pulses) > 0
                    
                    result = {
                        "indicator": indicator,
                        "type": indicator_type,
                        "is_malicious": is_malicious,
                        "pulses_count": len(malicious_pulses),
                        "malicious_pulses": malicious_pulses[:5]  # Limit to first 5 for readability
                    }
                    
                    return [types.TextContent(type="text", text=json.dumps(result, indent=2))]
                
                return [types.TextContent(type="text", text=f"Error: {response.status_code} - {response.text}")]
            
            elif name == "get_threat_actor":
                actor_name = arguments.get("name")
                
                if not actor_name:
                    raise ValueError("name is required")
                
                # Search for pulses that mention this threat actor
                response = await client.get(
                    f"{OTX_BASE_URL}/search/pulses",
                    params={"q": actor_name},
                    headers=headers
                )
                
                if response.status_code == 200:
                    results = response.json()
                    pulses = results.get("results", [])
                    
                    # Filter results to find pulses that have this actor as adversary
                    actor_pulses = []
                    for pulse in pulses:
                        if actor_name.lower() in pulse.get("adversary", "").lower():
                            actor_pulses.append(pulse)
                            
                            # Cache the pulse
                            pulse_id = pulse.get("id")
                            if pulse_id:
                                cache["pulses"][pulse_id] = pulse
                    
                    actor_info = {
                        "name": actor_name,
                        "pulse_count": len(actor_pulses),
                        "pulses": actor_pulses[:5]  # Limit to first 5 for readability
                    }
                    
                    # Cache the actor
                    cache["threat_actors"][actor_name] = actor_info
                    
                    return [types.TextContent(type="text", text=json.dumps(actor_info, indent=2))]
                
                return [types.TextContent(type="text", text=f"Error: {response.status_code} - {response.text}")]
            
            else:
                raise ValueError(f"Unknown tool: {name}")
                
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error executing {name}: {str(e)}")]


async def main():
    """Start the MCP server."""
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="alienvault-otx",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


# Entry point for the server
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="MCP server for AlienVault OTX API")
    parser.add_argument(
        "--api-key", 
        help="AlienVault OTX API key (can also be set via OTX_API_KEY env var)",
    )
    args = parser.parse_args()
    
    # Handle API key from args or environment
    if args.api_key:
        os.environ["OTX_API_KEY"] = args.api_key
    
    asyncio.run(main())
