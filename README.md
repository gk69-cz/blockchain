# Traffic Analysis Blockchain Application

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Flask-2.0%2B-green)
![License](https://img.shields.io/badge/license-MIT-green)

A Python-based blockchain application for learning traffic analysis, bot detection, and DDoS protection. This system uses blockchain technology to record and analyze suspicious network traffic patterns, implementing Proof of Work (PoW) challenges to protect against automated attacks.

## Table of Contents
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Documentation](#api-documentation)
- [Deployment](#deployment)
- [Security Features](#security-features)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Features

- ✅ **Traffic Analysis**: Real-time monitoring and analysis of HTTP requests
- ✅ **Bot Detection**: Advanced bot profiling and suspicious activity detection
- ✅ **Blockchain Recording**: Immutable record of traffic analysis results
- ✅ **Proof of Work Protection**: PoW challenges to prevent DDoS attacks
- ✅ **IP Blocking**: Automatic blocking of suspicious IP addresses
- ✅ **Batch Analysis**: Intelligent batching of requests for efficient analysis
- ✅ **TTL Analysis**: Network packet TTL obfuscation detection
- ✅ **SYN Flood Detection**: Monitor for SYN flood attacks
- ✅ **Mining System**: User mining with blockchain rewards
- ✅ **REST API**: Complete API for blockchain and traffic data

## Prerequisites

Before running this application, ensure you have:

- **Python 3.8 or higher**
- **pip** (Python package installer)
- **Root/Administrator privileges** (for raw socket operations)
- **Virtual environment** (recommended)

### System Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3-dev python3-pip build-essential

# CentOS/RHEL
sudo yum install python3-devel python3-pip gcc

# macOS
brew install python3
```

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/gk69-cz/blockchain.git
cd blockchain
```

### 2. Create Virtual Environment
```bash
# Create virtual environment
python3 -m venv blockchain_env

# Activate virtual environment
# On Linux/macOS:
source blockchain_env/bin/activate
# On Windows:
blockchain_env\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install flask psutil
pip install -r requirements.txt  # if requirements.txt exists
```

### 4. Create Necessary Directories
```bash
mkdir -p logs
mkdir -p templates
mkdir -p static
```

## Configuration

The application uses several configuration parameters that can be adjusted in `main.py`:

### Key Configuration Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `BATCH_SIZE` | Number of requests to batch before analysis | `20` |
| `ANALYSIS_WINDOW` | Time window for traffic analysis (seconds) | `60` |
| `BLOCK_DURATION` | IP blocking duration (seconds) | `300` |
| `HIGH_RPM_THRESHOLD` | Requests per minute threshold for suspicion | Variable |
| `SYN_FLOOD_THRESHOLD` | SYN flood detection threshold | `100` |

### Environment Setup

Create necessary JSON files:
```bash
touch blockchain.json
touch bot_profiles.json
touch ip_tracking.json
touch usermined.json
touch to_block.json
```

## Usage

### Running the Application

#### 1. Start the Traffic Analysis Server
```bash
# Standard execution
python main.py

# With elevated privileges (for TTL analysis)
sudo python main.py
```

#### 2. Access the Web Interface
Open your browser and navigate to:
```
http://localhost:8081
```

### Basic Operations

#### Access Protected Routes
The application will automatically present PoW challenges:
```bash
# Navigate to main page
curl http://localhost:8081/

# Access protected route
curl http://localhost:8081/protected
```

#### API Operations

**Add a Traffic Analysis Transaction:**
```bash
curl -X POST http://localhost:8081/api/blockchain/add-transaction \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.100",
    "headers_present": true,
    "ttl_obfuscation": false,
    "legitimacy_score": 7.5,
    "is_trustworthy": true
  }'
```

**Mine a Block:**
```bash
curl -X GET http://localhost:8081/api/blockchain/mine
```

**View Blockchain:**
```bash
curl -X GET http://localhost:8081/api/blockchain/chain
```

**Search by IP:**
```bash
curl -X POST http://localhost:8081/api/blockchain/search \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100"}'
```

## API Documentation

### Core Blockchain Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/blockchain/add-transaction` | Add traffic analysis transaction |
| `GET` | `/api/blockchain/mine` | Mine pending transactions |
| `GET` | `/api/blockchain/chain` | Get full blockchain |
| `GET` | `/api/blockchain/pending` | Get pending transactions |
| `GET` | `/api/blockchain/userblocks` | Get user mined blocks |
| `POST` | `/api/blockchain/search` | Search transactions by IP |

### Traffic Analysis Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/analyze-now` | Perform deep traffic analysis |
| `GET` | `/api/start-analyzer` | Start traffic analyzer |
| `GET` | `/api/bot-details` | Get bot profile information |

### Proof of Work Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/pow-challenge` | Get PoW challenge |
| `POST` | `/api/pow-submit` | Submit PoW solution |

### Transaction Schema

Traffic analysis transactions include:

```json
{
  "ip": "192.168.1.100",
  "headers_present": true,
  "ttl_obfuscation": false,
  "legitimacy_score": 7.5,
  "is_trustworthy": true,
  "timestamp": 1642780800.123
}
```

## Deployment

### Production Deployment

#### 1. Install Production Server
```bash
pip install gunicorn
```

#### 2. Create Gunicorn Configuration
Create `gunicorn.conf.py`:
```python
bind = "0.0.0.0:8081"
workers = 4
worker_class = "sync"
timeout = 60
max_requests = 1000
preload_app = True
```

#### 3. Start with Gunicorn
```bash
sudo gunicorn --config gunicorn.conf.py main:app
```

#### 4. Systemd Service
Create `/etc/systemd/system/blockchain-analyzer.service`:
```ini
[Unit]
Description=Blockchain Traffic Analyzer
After=network.target

[Service]
User=root
WorkingDirectory=/path/to/blockchain
Environment=PATH=/path/to/blockchain/blockchain_env/bin
ExecStart=/path/to/blockchain/blockchain_env/bin/gunicorn --config gunicorn.conf.py main:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable blockchain-analyzer
sudo systemctl start blockchain-analyzer
```

### Docker Deployment

#### 1. Create Dockerfile
```dockerfile
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create necessary directories
RUN mkdir -p logs

EXPOSE 8081

CMD ["python", "main.py"]
```

#### 2. Build and Run
```bash
# Build image
docker build -t blockchain-analyzer .

# Run container with privileges for raw sockets
docker run -d \
  --name blockchain-analyzer \
  --privileged \
  -p 8081:8081 \
  -v $(pwd)/data:/app/data \
  blockchain-analyzer
```

### Reverse Proxy Configuration

#### Nginx Configuration
```nginx
upstream blockchain_analyzer {
    server 127.0.0.1:8081;
}

server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://blockchain_analyzer;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Important for PoW challenges
        proxy_read_timeout 300;
        proxy_connect_timeout 300;
    }
}
```

## Security Features

### Traffic Analysis Protection

1. **Batch Analysis**: Groups requests for intelligent threat detection
2. **Rate Limiting**: Automatic IP blocking for excessive requests
3. **User-Agent Analysis**: Detection of suspicious browser signatures
4. **Header Validation**: Missing or malformed header detection
5. **TTL Analysis**: Network packet obfuscation detection

### Proof of Work System

- **Dynamic Difficulty**: Adjusts based on server load
- **Challenge Verification**: Cryptographic proof validation
- **DDoS Mitigation**: Computational requirements deter attacks

### Blockchain Security

- **Immutable Records**: All traffic analysis results permanently recorded
- **Proof of Work Mining**: Secure block creation process
- **Transaction Validation**: Comprehensive data integrity checks

## Development

### Project Structure
```
blockchain/
├── main.py                 # Flask application and main logic
├── logging_fix.py         # Centralized logging configuration
├── blockchain/
│   └── blockchain_module.py # Core blockchain implementation
├── pow/
│   └── js_threshhold_logic.py # PoW and traffic analysis
├── bots/
│   └── botprofile.py      # Bot detection and profiling
├── server/
│   └── ipblocker.py       # IP blocking utilities
├── utils/
│   └── shared_data.py     # Shared constants and data
├── logs/                  # Application logs
├── templates/             # HTML templates (if any)
└── static/               # Static files (if any)
```

### Running Tests

```bash
# Test basic functionality
python -c "from blockchain.blockchain_module import Blockchain; b = Blockchain(); print('Blockchain initialized')"

# Test PoW system
curl -X GET http://localhost:8081/api/pow-challenge

# Test traffic analysis
curl -X GET http://localhost:8081/api/analyze-now
```

### Development Mode

```bash
# Enable debug logging
export FLASK_ENV=development
export FLASK_DEBUG=1

# Run with detailed logs
python main.py
```

## Troubleshooting

### Common Issues

#### Permission Errors (TTL Analysis)
```bash
# Run with sudo for raw socket access
sudo python main.py

# Or adjust capabilities
sudo setcap cap_net_raw+ep /usr/bin/python3
```

#### Port Already in Use
```bash
# Find process using port 8081
sudo lsof -i :8081

# Kill the process
sudo kill -9 <PID>

# Or change port in main.py
```

#### High CPU Usage During PoW
- Reduce difficulty in `get_dynamic_difficulty()` function
- Implement PoW caching for repeated clients

#### Memory Issues
```bash
# Monitor memory usage
python -c "import psutil; print(f'Memory: {psutil.virtual_memory().percent}%')"

# Clear old log files
find logs/ -name "*.log" -mtime +7 -delete
```

#### Blockchain File Corruption
```bash
# Backup and reset blockchain
cp blockchain.json blockchain.json.backup
echo '{"chain": [], "pending_transactions": []}' > blockchain.json
```

### Log Files

- **Application logs**: `logs/app.log`
- **Traffic analysis**: `logs/traffic_analyzer.log`
- **Critical events**: `logs/critical.log`

### Network Analysis Tools

```bash
# Monitor SYN connections
netstat -ant | grep SYN_RECV | wc -l

# Check network interface statistics
cat /proc/net/dev

# Monitor real-time connections
watch -n 1 'netstat -ant | grep :8081'
```

## Performance Optimization

### For High Traffic Environments

1. **Batch Size Tuning**: Adjust `BATCH_SIZE` based on traffic volume
2. **Analysis Window**: Optimize `ANALYSIS_WINDOW` for your use case
3. **Worker Processes**: Use multiple Gunicorn workers
4. **Database**: Consider using PostgreSQL for large datasets
5. **Caching**: Implement Redis for PoW challenge caching

### Monitoring

```bash
# Monitor application performance
pip install psutil
python -c "import psutil; print(f'CPU: {psutil.cpu_percent()}%, Memory: {psutil.virtual_memory().percent}%')"
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Educational Use

This blockchain application is designed for learning purposes and demonstrates:

- **Traffic Analysis Techniques**: Real-world network security patterns
- **Blockchain Implementation**: Practical blockchain development
- **DDoS Protection**: Modern attack mitigation strategies
- **Bot Detection**: Machine learning approaches to traffic classification

---

**⚠️ Important**: This application requires elevated privileges for full functionality (TTL analysis). Always review security implications before deployment.