# API-AutoFuzz - Automated API Security Testing Tool

An automated tool for detecting BOLA (Broken Object Level Authorization) vulnerabilities in APIs with OWASP ZAP integration.

## Key Automation Features

- **Automatic OpenAPI parsing** - analyzes all endpoints and parameters from specification
- **Automatic payload generation** - creates test variations for BOLA detection
- **Asynchronous execution** - parallel processing of up to 24 requests simultaneously
- **Automatic vulnerability detection** - identifies suspicious endpoints based on HTTP responses
- **Automatic report generation** - saves timestamped results without manual intervention
- **OWASP ZAP integration** - uses configured authenticated session automatically

## What is BOLA?

BOLA is when an API doesn't check if you should have access to specific data. For example, if changing `/users/123` to `/users/456` lets you see someone else's data, that's a BOLA vulnerability.

## Requirements

- Python 3.6+
- OWASP ZAP running on port 8080
- **Important**: ZAP must have an authenticated session configured before running the fuzzer
- Python package: `httpx`

## Installation

1. Clone the repository
2. Install dependencies:
```bash
pip install httpx
```
3. Copy the example config:
```bash
cp config.example.json config.json
```
4. Edit `config.json` with your API details

## Usage

### Using config file:
```bash
python fuzzer.py
```

### Using command-line arguments:
```bash
python fuzzer.py --url https://api.example.com --file openapi.json
```

### Options:
- `--url` - Target API base URL
- `--file` - Path to OpenAPI/Swagger file
- `--config` - Path to config file (default: config.json)

## How Automation Works

1. **Automatic API Analysis** - Reads OpenAPI specification and identifies all endpoints with path parameters (like `/users/{id}`)

2. **Automatic Test Generation** - Creates payload set for each parameter: valid IDs (1, 24), boundary values (0, -5), invalid types (text, *&^$), special characters (6,5)

3. **Asynchronous Execution** - Processes up to 24 requests in parallel with automatic timeout management and error handling

4. **Automatic Vulnerability Detection** - Analyzes HTTP responses and identifies endpoints returning 200 OK with fuzzed payloads, indicating potential missing authorization checks

5. **Automatic Report Generation** - Creates detailed timestamped reports with suspicious endpoints and error logs

## Setting up ZAP

1. Start OWASP ZAP
2. Configure authentication for your target API
3. Create an authenticated session
4. Make sure ZAP is running on `localhost:8080`

The fuzzer will automatically use ZAP's session for authentication in all requests.

## Output

Results are automatically saved to `results/results_[timestamp].txt` with all endpoints that returned 200 OK during fuzzing.

## Limitations

- Requires valid OpenAPI specification
- ZAP must have configured authentication
- Consider API rate limiting when testing
- Recommended for staging/test environments only

## Skills Acquired

This project demonstrates proficiency in:

**Security Testing:**
- BOLA/IDOR vulnerability detection techniques
- API security testing methodologies
- Integration with industry-standard tools (OWASP ZAP)
- Understanding of authorization vulnerabilities

**Python Development:**
- Asynchronous programming with `asyncio` and `httpx`
- REST API interaction and HTTP protocol
- JSON parsing and OpenAPI specification handling
- Command-line argument parsing with `argparse`
- Configuration management
- Error handling and exception management

**Software Engineering:**
- Clean code organization and structure
- Automated testing tool development
- Rate limiting and concurrency control (semaphores)
- File I/O operations and report generation
- Proxy integration and SSL/TLS handling

**Problem Solving:**
- Automated vulnerability scanning logic
- Parallel request processing optimization
- Real-time progress tracking and monitoring
- Systematic approach to security testing
