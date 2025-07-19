# HTTP MCP Server

A Model Context Protocol (MCP) server that provides HTTP debugging and testing capabilities for AI-driven web scraping workflows.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

## 🚀 Features

- **🌐 HTTP Requests**: Make GET, POST, PUT, DELETE requests with full control over headers, data, and timeouts
- **📊 Response Analysis**: Deep analysis of response headers, status codes, content types, and performance metrics
- **⚡ Performance Testing**: Profile request performance with multiple iterations and statistical analysis
- **🔍 Debug Workflows**: Compare responses, validate endpoints, and debug HTTP interactions
- **🔗 Integration Ready**: Designed to work seamlessly with Debug MCP and Playwright MCP servers

## 📦 Installation

### From GitHub (Recommended)

```bash
pip install git+https://github.com/alexwilliamson/http-mcp-server.git
```

### For Development

```bash
git clone https://github.com/alexwilliamson/http-mcp-server.git
cd http-mcp-server
pip install -e .
```

## 🏃 Quick Start

### 1. Start the Server

```bash
# HTTP transport (recommended for AI agents)
http-mcp http --port 8933

# Or stdio transport (for direct MCP clients)
http-mcp stdio
```

### 2. Connect from AI Agent

```python
from mcp.client.sse import sse_client
from mcp import ClientSession
from langchain_mcp_adapters.tools import load_mcp_tools

async with sse_client("http://localhost:8933/sse") as (read, write):
    async with ClientSession(read, write) as session:
        await session.initialize()
        http_tools = await load_mcp_tools(session)
        
        # Now you have 8 powerful HTTP debugging tools available!
        for tool in http_tools:
            print(f"Available: {tool.name}")
```

### 3. Use in Scraper Testing

This server enables AI agents to test and debug HTTP aspects of web scraping:
1. Test API endpoints directly
2. Compare browser vs direct HTTP responses  
3. Analyze headers and response structure
4. Profile performance and identify bottlenecks
5. Debug authentication and cookies

## 🛠️ Available Tools

### Core HTTP Operations
| Tool | Description | Example Use |
|------|-------------|-------------|
| `make_request` | Make HTTP requests with full control | Test API endpoints, download pages |
| `analyze_response` | Deep response analysis | Understand content type, encoding, structure |
| `extract_headers` | Categorize and analyze headers | Check security headers, caching rules |
| `validate_status` | Validate response status codes | Ensure requests succeed as expected |

### Advanced Debug Tools
| Tool | Description | Example Use |
|------|-------------|-------------|
| `debug_request` | Request with session logging | Debug failing requests with artifacts |
| `compare_responses` | Compare two HTTP responses | Browser vs API response differences |
| `profile_performance` | Multi-iteration performance testing | Find fastest endpoints, identify slowdowns |

### Utility Tools
| Tool | Description | Example Use |
|------|-------------|-------------|
| `close_http_client` | Clean shutdown of HTTP client | Proper cleanup in workflows |

## 🏗️ Architecture Integration

This server is part of a complete AI scraper debugging stack:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Playwright MCP │    │   Debug MCP     │    │   HTTP MCP      │
│  Browser Auto   │    │  File/Terminal  │    │  This Server    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────────┐
                    │    AI Agent         │
                    │                     │
                    │ 1. Plan Scraping    │
                    │ 2. Test HTTP First  │
                    │ 3. Generate Code    │
                    │ 4. Debug & Fix      │
                    └─────────────────────┘
```

## 🔧 Usage Examples

### Basic HTTP Request

```python
# Make a simple GET request
response = await make_request("GET", "https://api.example.com/data")

# Analyze the response
analysis = await analyze_response(response)
print(f"Content type: {analysis.content_type}")
print(f"Response time: {analysis.performance_metrics['response_time_ms']}ms")
```

### Debug API Endpoint

```python
# Debug request with session logging
debug_result = await debug_request({
    "method": "POST",
    "url": "https://api.example.com/search",
    "headers": {"Authorization": "Bearer token"},
    "data": {"query": "test"}
}, session_id="debug-123")

# Check if request succeeded
if debug_result["success"]:
    response = debug_result["response"]
    analysis = debug_result["analysis"]
    print(f"API returned {len(response['content'])} bytes")
else:
    print(f"Request failed: {debug_result['error']}")
```

### Compare Browser vs API

```python
# Get response from browser (via Playwright MCP)
browser_response = await playwright_get_page_content(url)

# Get same content via direct HTTP
api_response = await make_request("GET", url)

# Compare responses
comparison = await compare_responses(browser_response, api_response)
print(f"Content identical: {comparison['content_similarity']['identical']}")
print(f"Header differences: {len(comparison['header_differences']['value_differences'])}")
```

### Performance Profiling

```python
# Profile endpoint performance
profile = await profile_performance("https://api.example.com/data", iterations=5)

stats = profile["statistics"]
print(f"Average response time: {stats['avg_response_time_ms']:.2f}ms")
print(f"Success rate: {stats['success_rate']:.1f}%")
```

## 📊 Response Analysis Features

### Content Analysis
- Content type detection (JSON, HTML, XML, etc.)
- Encoding detection and validation
- Size metrics and compression analysis

### Header Analysis
- Security headers audit (CSP, HSTS, X-Frame-Options)
- Caching headers analysis (Cache-Control, ETag)
- Server information extraction
- Custom header categorization

### Performance Metrics
- Response time measurement
- Content size analysis
- Transfer speed calculation
- Statistical analysis across multiple requests

## 🧪 Testing

```bash
# Test the server directly
python -m http_mcp.server http --port 8933

# In another terminal, test basic functionality:
curl -X POST http://localhost:8933/mcp \
  -H "Content-Type: application/json" \
  -d '{"method": "tools/list"}'
```

## 🔧 Configuration

### Request Defaults

The server uses sensible defaults:
- **Timeout**: 30 seconds
- **Max Redirects**: 10
- **User Agent**: Standard HTTP client
- **SSL Verification**: Enabled

### Debug Artifacts

When using `debug_request` with session management:

```
debug_artifacts/sessions/{session_id}/responses/
├── http_response_1234567890.json      # Full response data
├── http_content_1234567890.html       # Response content (if HTML)
└── http_analysis_1234567890.json      # Analysis results
```

## 🐛 Troubleshooting

### Common Issues

1. **SSL Errors**: For development, consider SSL verification settings
2. **Timeout Issues**: Adjust timeout for slow endpoints
3. **Memory Usage**: Large responses are handled efficiently with streaming
4. **Rate Limiting**: Built-in delays between performance test iterations

### Debug Mode

Enable detailed logging:

```bash
http-mcp http --port 8933 --log-level DEBUG
```

## 🤝 Integration Examples

### With Debug MCP

```python
# Combined HTTP testing and file operations
http_response = await make_request("GET", target_url)
await write_file("debug_response.html", http_response["content"])
await search_file("debug_response.html", "error")
```

### With LangGraph Workflows

```python
# HTTP testing in scraper debug workflow
if strategy == "api_direct":
    # Test API endpoint first
    api_response = await make_request("GET", api_url)
    api_analysis = await analyze_response(api_response)
    
    if api_analysis.is_json:
        # Generate API scraper
        scraper_code = generate_api_scraper(api_response)
    else:
        # Fall back to HTML scraping
        scraper_code = generate_html_scraper(api_response)
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built for AI-driven development workflows
- Integrates with [Model Context Protocol (MCP)](https://github.com/modelcontextprotocol)
- Designed for [LangGraph](https://github.com/langchain-ai/langgraph) agent workflows
- HTTP client powered by [httpx](https://github.com/encode/httpx)
- Part of automated scraper development pipeline