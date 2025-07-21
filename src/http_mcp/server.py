"""HTTP MCP Server - Main server implementation."""

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import aiofiles
import httpx
from mcp.server.fastmcp import Context, FastMCP
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# === Data Models ===

class HTTPResponse(BaseModel):
    """HTTP response data model."""
    status_code: int
    headers: Dict[str, str] = Field(default_factory=dict)
    content: str
    elapsed_ms: float
    url: str
    method: str
    success: bool
    error: Optional[str] = None

class RequestConfig(BaseModel):
    """HTTP request configuration."""
    method: str = "GET"
    url: str
    headers: Dict[str, str] = Field(default_factory=dict)
    data: Optional[Union[str, Dict[str, Any]]] = None
    timeout: Optional[int] = 30

class ResponseAnalysis(BaseModel):
    """Response analysis result."""
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    encoding: Optional[str] = None
    is_json: bool = False
    is_html: bool = False
    status_category: str
    headers_analysis: Dict[str, Any] = Field(default_factory=dict)
    performance_metrics: Dict[str, Any] = Field(default_factory=dict)

# === Global HTTP Client ===
http_client: Optional[httpx.AsyncClient] = None

async def get_http_client() -> httpx.AsyncClient:
    """Get or create HTTP client."""
    global http_client
    if http_client is None:
        http_client = httpx.AsyncClient(timeout=30.0)
    return http_client

# === MCP Server Setup ===
mcp = FastMCP("http-mcp")

# === HTTP Operations Tools ===

@mcp.tool()
async def make_request(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[Union[str, Dict[str, Any]]] = None,
    timeout: Optional[int] = 30
) -> HTTPResponse:
    """Make an HTTP request to a specified URL with configurable options.
    
    This is the core HTTP client tool that sends requests using any standard HTTP method
    and returns comprehensive response data including headers, content, timing metrics,
    and success status. Automatically handles JSON serialization and content-type headers.
    
    Args:
        method: HTTP method to use (e.g., "GET", "POST", "PUT", "DELETE", "PATCH")
        url: Target URL for the request (e.g., "https://api.example.com/users", "http://localhost:3000/api/data")
        headers: Optional dictionary of HTTP headers to send (e.g., {"Authorization": "Bearer token", "User-Agent": "MyApp/1.0"})
        data: Optional request body data - can be a string or dict (dict will be JSON-serialized automatically)
        timeout: Request timeout in seconds, defaults to 30 seconds
    
    Returns:
        HTTPResponse with status_code, headers dict, content string, elapsed_ms timing, url, method, success boolean, and optional error message
    """
    try:
        client = await get_http_client()
        start_time = time.time()
        
        # Prepare request data
        request_headers = headers or {}
        request_data = data
        
        if isinstance(data, dict):
            request_data = json.dumps(data)
            request_headers.setdefault("Content-Type", "application/json")
        
        response = await client.request(
            method=method.upper(),
            url=url,
            headers=request_headers,
            content=request_data,
            timeout=timeout
        )
        
        elapsed_ms = (time.time() - start_time) * 1000
        
        return HTTPResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            content=response.text,
            elapsed_ms=elapsed_ms,
            url=str(response.url),
            method=method.upper(),
            success=200 <= response.status_code < 300
        )
        
    except httpx.TimeoutException:
        return HTTPResponse(
            status_code=0,
            content="",
            elapsed_ms=timeout * 1000 if timeout else 30000,
            url=url,
            method=method.upper(),
            success=False,
            error="Request timed out"
        )
    except Exception as e:
        return HTTPResponse(
            status_code=0,
            content="",
            elapsed_ms=0,
            url=url,
            method=method.upper(),
            success=False,
            error=str(e)
        )

@mcp.tool()
async def analyze_response(response_data: Dict[str, Any]) -> ResponseAnalysis:
    """Analyze HTTP response data to extract metadata, performance metrics, and content characteristics.
    
    This tool takes the response from make_request and provides detailed analysis including
    content type detection, security header analysis, caching information, and performance metrics.
    
    Args:
        response_data: Dictionary containing HTTP response data from make_request (must include 'headers', 'content', 'status_code', 'elapsed_ms' keys)
    
    Returns:
        ResponseAnalysis with content_type, content_length, is_json/is_html flags, status_category, headers_analysis, and performance_metrics
    """
    try:
        headers = response_data.get("headers", {})
        content = response_data.get("content", "")
        status_code = response_data.get("status_code", 0)
        elapsed_ms = response_data.get("elapsed_ms", 0)
        
        # Content analysis
        content_type = headers.get("content-type", "").lower()
        content_length = len(content)
        is_json = "application/json" in content_type or content.strip().startswith(("{", "["))
        is_html = "text/html" in content_type or content.strip().startswith("<!DOCTYPE") or "<html" in content[:100].lower()
        
        # Status category
        if status_code == 0:
            status_category = "error"
        elif 200 <= status_code < 300:
            status_category = "success"
        elif 300 <= status_code < 400:
            status_category = "redirect"
        elif 400 <= status_code < 500:
            status_category = "client_error"
        elif status_code >= 500:
            status_category = "server_error"
        else:
            status_category = "unknown"
        
        # Headers analysis
        headers_analysis = {
            "security_headers": {
                "content_security_policy": "content-security-policy" in headers,
                "strict_transport_security": "strict-transport-security" in headers,
                "x_frame_options": "x-frame-options" in headers,
                "x_content_type_options": "x-content-type-options" in headers
            },
            "caching_headers": {
                "cache_control": headers.get("cache-control"),
                "expires": headers.get("expires"),
                "etag": headers.get("etag")
            },
            "server_info": {
                "server": headers.get("server"),
                "x_powered_by": headers.get("x-powered-by")
            }
        }
        
        # Performance metrics
        performance_metrics = {
            "response_time_ms": elapsed_ms,
            "content_size_bytes": content_length,
            "response_speed_kbps": (content_length / 1024) / (elapsed_ms / 1000) if elapsed_ms > 0 else 0
        }
        
        return ResponseAnalysis(
            content_type=content_type,
            content_length=content_length,
            is_json=is_json,
            is_html=is_html,
            status_category=status_category,
            headers_analysis=headers_analysis,
            performance_metrics=performance_metrics
        )
        
    except Exception as e:
        return ResponseAnalysis(
            status_category="error",
            headers_analysis={"error": str(e)}
        )

@mcp.tool()
async def extract_headers(response_data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract and categorize HTTP response headers into logical groups.
    
    This tool organizes response headers into categories (security, caching, content, server, custom)
    to help understand the server configuration and response characteristics.
    
    Args:
        response_data: Dictionary containing HTTP response data with 'headers' key from make_request
    
    Returns:
        Dict with 'success' status, 'categorized_headers' containing security/caching/content/server/custom sections, and 'total_headers' count
    """
    try:
        headers = response_data.get("headers", {})
        
        categorized_headers = {
            "security": {},
            "caching": {},
            "content": {},
            "server": {},
            "custom": {}
        }
        
        security_headers = ["content-security-policy", "strict-transport-security", 
                           "x-frame-options", "x-content-type-options", "x-xss-protection"]
        caching_headers = ["cache-control", "expires", "etag", "last-modified"]
        content_headers = ["content-type", "content-length", "content-encoding"]
        server_headers = ["server", "x-powered-by", "x-aspnet-version"]
        
        for header_name, header_value in headers.items():
            header_lower = header_name.lower()
            
            if header_lower in security_headers:
                categorized_headers["security"][header_name] = header_value
            elif header_lower in caching_headers:
                categorized_headers["caching"][header_name] = header_value
            elif header_lower in content_headers:
                categorized_headers["content"][header_name] = header_value
            elif header_lower in server_headers:
                categorized_headers["server"][header_name] = header_value
            else:
                categorized_headers["custom"][header_name] = header_value
        
        return {
            "success": True,
            "categorized_headers": categorized_headers,
            "total_headers": len(headers)
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
async def validate_status(response_data: Dict[str, Any], expected_status: int) -> Dict[str, Any]:
    """Validate that an HTTP response has the expected status code.
    
    This tool checks if the actual response status matches what was expected,
    useful for API testing and validation workflows.
    
    Args:
        response_data: Dictionary containing HTTP response data with 'status_code' key from make_request
        expected_status: The HTTP status code you expected (e.g., 200, 201, 404, 500)
    
    Returns:
        Dict with 'success' status, 'actual_status', 'expected_status', 'status_match' boolean, and 'status_category' classification
    """
    try:
        actual_status = response_data.get("status_code", 0)
        
        return {
            "success": True,
            "actual_status": actual_status,
            "expected_status": expected_status,
            "status_match": actual_status == expected_status,
            "status_category": "success" if 200 <= actual_status < 300 else "error"
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}

# === Debug Tools ===

@mcp.tool()
async def debug_request(
    request_config: Dict[str, Any],
    session_id: Optional[str] = None
) -> Dict[str, Any]:
    """Execute an HTTP request with comprehensive debugging, logging, and artifact storage.
    
    This tool combines request execution with detailed analysis and optionally saves
    debug artifacts to disk. Perfect for troubleshooting API issues or detailed inspection.
    
    Args:
        request_config: Dictionary with request configuration containing:
            - 'method': HTTP method (required)
            - 'url': Target URL (required)
            - 'headers': Optional headers dict
            - 'data': Optional request body
            - 'timeout': Optional timeout in seconds
        session_id: Optional session identifier for organizing debug artifacts in /tmp/debug_artifacts/sessions/{session_id}/
    
    Returns:
        Dict with 'success' status, 'response' data, 'analysis' results, and 'artifacts' info (file paths if session_id provided)
    """
    try:
        # Extract request configuration
        method = request_config.get("method", "GET")
        url = request_config.get("url")
        headers = request_config.get("headers", {})
        data = request_config.get("data")
        timeout = request_config.get("timeout", 30)
        
        if not url:
            return {"success": False, "error": "URL is required"}
        
        # Make the request
        response = await make_request(method, url, headers, data, timeout)
        
        # Analyze the response
        analysis = await analyze_response(response.model_dump())
        
        # Save artifacts if session provided
        artifacts = {}
        if session_id:
            try:
                debug_dir = Path(f"/tmp/debug_artifacts/sessions/{session_id}/responses")
                debug_dir.mkdir(parents=True, exist_ok=True)
                
                # Save response
                response_file = debug_dir / f"http_response_{int(time.time())}.json"
                async with aiofiles.open(response_file, 'w') as f:
                    await f.write(response.model_dump_json(indent=2))
                
                # Save content if HTML
                if analysis.is_html:
                    html_file = debug_dir / f"http_content_{int(time.time())}.html"
                    async with aiofiles.open(html_file, 'w') as f:
                        await f.write(response.content)
                    artifacts["html_file"] = str(html_file)
                
                artifacts["response_file"] = str(response_file)
                
            except Exception as e:
                artifacts["save_error"] = str(e)
        
        return {
            "success": True,
            "response": response.model_dump(),
            "analysis": analysis.model_dump(),
            "artifacts": artifacts
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
async def compare_responses(
    response1_data: Dict[str, Any],
    response2_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Compare two HTTP responses and identify differences in status, headers, and content.
    
    This tool performs detailed comparison between two response objects, highlighting
    differences in status codes, headers, and content characteristics. Useful for A/B testing,
    API version comparison, or debugging response changes.
    
    Args:
        response1_data: First HTTP response dictionary from make_request
        response2_data: Second HTTP response dictionary from make_request
    
    Returns:
        Dict with 'success' status, 'comparison' metrics, 'header_differences' breakdown, and 'content_similarity' analysis
    """
    try:
        r1_status = response1_data.get("status_code", 0)
        r2_status = response2_data.get("status_code", 0)
        
        r1_headers = response1_data.get("headers", {})
        r2_headers = response2_data.get("headers", {})
        
        r1_content = response1_data.get("content", "")
        r2_content = response2_data.get("content", "")
        
        # Compare basic metrics
        comparison = {
            "status_codes": {
                "response1": r1_status,
                "response2": r2_status,
                "match": r1_status == r2_status
            },
            "content_length": {
                "response1": len(r1_content),
                "response2": len(r2_content),
                "match": len(r1_content) == len(r2_content)
            },
            "headers_count": {
                "response1": len(r1_headers),
                "response2": len(r2_headers),
                "match": len(r1_headers) == len(r2_headers)
            }
        }
        
        # Compare headers
        header_diff = {
            "only_in_response1": [],
            "only_in_response2": [],
            "value_differences": []
        }
        
        all_header_keys = set(r1_headers.keys()) | set(r2_headers.keys())
        for key in all_header_keys:
            if key in r1_headers and key not in r2_headers:
                header_diff["only_in_response1"].append(key)
            elif key in r2_headers and key not in r1_headers:
                header_diff["only_in_response2"].append(key)
            elif r1_headers[key] != r2_headers[key]:
                header_diff["value_differences"].append({
                    "header": key,
                    "response1_value": r1_headers[key],
                    "response2_value": r2_headers[key]
                })
        
        # Content similarity (basic)
        content_similarity = {
            "identical": r1_content == r2_content,
            "length_difference": len(r2_content) - len(r1_content),
            "similarity_ratio": len(set(r1_content) & set(r2_content)) / max(len(set(r1_content)), len(set(r2_content)), 1)
        }
        
        return {
            "success": True,
            "comparison": comparison,
            "header_differences": header_diff,
            "content_similarity": content_similarity
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
async def profile_performance(url: str, iterations: int = 3) -> Dict[str, Any]:
    """Measure HTTP request performance over multiple iterations to analyze consistency and speed.
    
    This tool sends multiple GET requests to the same URL and calculates performance statistics
    including average/min/max response times, success rates, and content size metrics.
    
    Args:
        url: Target URL to profile (e.g., "https://api.example.com/health")
        iterations: Number of requests to send (1-10, defaults to 3)
    
    Returns:
        Dict with 'success' status, 'url', 'iterations', individual 'results' array, and aggregate 'statistics'
    """
    try:
        if iterations <= 0 or iterations > 10:
            return {"success": False, "error": "Iterations must be between 1 and 10"}
        
        results = []
        for i in range(iterations):
            response = await make_request("GET", url)
            results.append({
                "iteration": i + 1,
                "status_code": response.status_code,
                "elapsed_ms": response.elapsed_ms,
                "content_length": len(response.content),
                "success": response.success
            })
            
            # Small delay between requests
            await asyncio.sleep(0.1)
        
        # Calculate statistics
        successful_results = [r for r in results if r["success"]]
        if successful_results:
            response_times = [r["elapsed_ms"] for r in successful_results]
            content_lengths = [r["content_length"] for r in successful_results]
            
            stats = {
                "avg_response_time_ms": sum(response_times) / len(response_times),
                "min_response_time_ms": min(response_times),
                "max_response_time_ms": max(response_times),
                "avg_content_length": sum(content_lengths) / len(content_lengths),
                "success_rate": len(successful_results) / len(results) * 100
            }
        else:
            stats = {"error": "No successful requests"}
        
        return {
            "success": True,
            "url": url,
            "iterations": iterations,
            "results": results,
            "statistics": stats
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}

# === Server Cleanup ===

@mcp.tool()
async def close_http_client() -> Dict[str, Any]:
    """Close the global HTTP client connection to free resources.
    
    This cleanup tool closes the persistent HTTP client connection and releases
    associated resources. Should be called when HTTP operations are complete
    or when shutting down the MCP server.
    
    Returns:
        Dict with 'success' status and 'message' confirming closure, or error details
    """
    global http_client
    try:
        if http_client:
            await http_client.aclose()
            http_client = None
        return {"success": True, "message": "HTTP client closed"}
    except Exception as e:
        return {"success": False, "error": str(e)}

# === Main Server Setup ===

def main():
    """Main server entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="HTTP MCP Server")
    parser.add_argument("transport", choices=["stdio", "http"], help="Transport type")
    parser.add_argument("--port", type=int, default=8933, help="HTTP port")
    
    args = parser.parse_args()
    
    if args.transport == "stdio":
        mcp.run()
    else:
        # HTTP transport using StreamableHTTP
        import uvicorn
        app = mcp.streamable_http_app()
        uvicorn.run(app, host="0.0.0.0", port=args.port)

if __name__ == "__main__":
    main()