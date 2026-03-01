# Gideon MCP Security Tools Server
# Based on Kali Linux for comprehensive security tool support

FROM kalilinux/kali-rolling:latest

LABEL maintainer="Gideon Team"
LABEL description="MCP server providing security tools for Gideon"

# Install security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core utilities
    curl \
    wget \
    git \
    jq \
    python3 \
    python3-pip \
    python3-venv \
    # Network tools
    nmap \
    masscan \
    # Web tools
    httpx-toolkit \
    nuclei \
    katana \
    ffuf \
    # Subdomain enumeration
    subfinder \
    amass \
    # DNS tools
    dnsutils \
    whois \
    # Development
    build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create Python virtual environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies for MCP server
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    sse-starlette \
    pydantic \
    httpx

# Download Nuclei templates
RUN nuclei -update-templates || true

# Create MCP server directory
WORKDIR /app

# Copy MCP server code
COPY server.py /app/
COPY tools/ /app/tools/

# Expose MCP port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run MCP server
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
