# Intelligence Aggregator

A unified threat intelligence platform built with Streamlit that integrates multiple cybersecurity data sources into one place.

## Features

- 🦠 **VirusTotal** - File and URL reputation scanning
- 🔌 **Shodan** - Internet-connected device discovery
- 🚨 **AlienVault OTX** - Open threat intelligence platform
- ⚠️ **AbuseIPDB** - IP reputation and abuse reports
- ℹ️ **IPInfo** - IP geolocation and metadata
- 🌐 **URLhaus** - Malicious URL database

## Supported Observable Types

- **IP Addresses** (IPv4) - Full support across all sources
- **Domains** - Reputation, DNS records, threat intelligence
- **URLs** - Malicious URL detection, categorization
- **File Hashes** - MD5, SHA1, SHA256 file reputation

## Quick Start

### 1. Clone/Download Project

```bash
cd intelligence-aggregator
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure API Keys

Copy `.env.example` to `.env` and add your API keys:

```bash
cp .env.example .env
```

Edit `.env` with your API credentials:
```
VIRUSTOTAL_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
OTX_API_KEY=your_key_here
IPINFO_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
```

### 4. Run Application

```bash
streamlit run app.py
```

The app will open in your browser at `http://localhost:8501`

## Getting API Keys

### VirusTotal
1. Go to https://www.virustotal.com/gui/settings/api
2. Sign up for a free account
3. Generate API key from settings

### Shodan
1. Visit https://shodan.io/
2. Create an account
3. Get API key from account page

### AlienVault OTX
1. Go to https://otx.alienvault.com/
2. Register for free
3. Create API key in account settings

### IPInfo
1. Visit https://ipinfo.io/
2. Sign up for free tier
3. Get API token from dashboard

### AbuseIPDB
1. Go to https://www.abuseipdb.com/
2. Create account
3. Generate API key from account

## Usage

1. **Enter Observable**: Paste an IP, domain, URL, or hash in the input field
2. **Select Sources**: Choose which threat intelligence sources to query
3. **Analyze**: Click the "Analyze" button
4. **Review Results**: See aggregated intelligence from all sources
5. **Export**: Download results as JSON or text report

## Project Structure

```
intelligence-aggregator/
├── app.py                      # Main Streamlit application
├── requirements.txt            # Python dependencies
├── .env.example               # Environment variables template
├── .streamlit/
│   └── config.toml           # Streamlit configuration
├── apis/                      # API integration modules
│   ├── __init__.py
│   ├── base.py               # Base API client class
│   ├── virustotal.py         # VirusTotal integration
│   ├── shodan.py             # Shodan integration
│   ├── otx.py                # AlienVault OTX integration
│   ├── ipinfo.py             # IPInfo integration
│   ├── abuseipdb.py          # AbuseIPDB integration
│   └── urlhaus.py            # URLhaus integration
├── utils/                     # Utility functions
│   ├── __init__.py
│   ├── config.py             # Configuration management
│   └── helpers.py            # Helper functions
└── data/                      # Data storage (optional)
```

## API Integration Architecture

Each API is implemented as a separate module inheriting from `BaseAPIClient`:

```python
from apis import VirusTotalAPI

# Initialize client
vt = VirusTotalAPI(api_key="your_key")

# Analyze observable
results = vt.analyze("8.8.8.8")

# Results are returned as structured dict
```

### Base Client Features

- Automatic retry on failures
- Timeout handling
- Error normalization
- Observable type classification
- Request session management

## Response Format

All analyzers return results in a standard format:

```json
{
  "source": "VirusTotal",
  "type": "ip",
  "observable": "8.8.8.8",
  "malicious": 0,
  "suspicious": 0,
  "undetected": 70,
  "country": "US",
  "asn": "AS15169",
  "raw_data": {...}
}
```

## Threat Level Classification

- 🔴 **Critical**: 10+ malicious detections
- 🟠 **High**: 5-9 malicious detections
- 🟡 **Medium**: 1-4 malicious or 5+ suspicious
- 🔵 **Low**: Suspicious detections only
- 🟢 **Clean**: No detections

## Deployment

### Streamlit Cloud

1. Push code to GitHub
2. Connect repository to Streamlit Cloud
3. Add secrets (API keys) in app settings
4. Deploy!

### Docker

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8501
CMD ["streamlit", "run", "app.py"]
```

### Netlify Functions (Alternative)

For a serverless backend, you can extract the API logic into AWS Lambda/Netlify Functions:

```python
# api_handler.py
import json
from apis import VirusTotalAPI

def handler(event, context):
    observable = event.get("observable")
    vt = VirusTotalAPI(api_key=os.getenv("VIRUSTOTAL_API_KEY"))
    result = vt.analyze(observable)
    
    return {
        "statusCode": 200,
        "body": json.dumps(result)
    }
```

## Features

### Multi-Source Aggregation
- Query multiple threat intelligence sources simultaneously
- Compare results across platforms
- Identify consensus on threat status

### Data Normalization
- Convert different API response formats to standard structure
- Easy to add new data sources
- Consistent error handling

### Results Export
- Export as JSON for integration with other tools
- Generate text reports for documentation
- Copy results for sharing

### Performance
- Built-in caching to avoid redundant queries
- Configurable timeouts
- Retry mechanism for transient failures

## Limitations

- Free API tier rate limits apply
- Some APIs have quota restrictions
- URLhaus is public/free, others require paid subscriptions for full access

## Security Considerations

- API keys stored in `.env` (not tracked in git)
- Never commit `.env` with real keys
- Use environment variables in production
- Consider using secrets management tools (AWS Secrets Manager, HashiCorp Vault)

## Troubleshooting

### "Invalid API Key"
- Verify API key in `.env` file
- Check API key hasn't expired
- Ensure you have the correct key type

### "Rate Limited"
- Wait before querying the same observable
- Upgrade to paid API tier for higher limits
- Implement query caching

### "Connection Timeout"
- Check your internet connection
- Verify API endpoint is accessible
- Increase `REQUEST_TIMEOUT` in `.env`

### "Observable not found"
- Verify observable format is correct
- Some sources may not have data for all observables
- Try other sources

## Contributing

To add a new intelligence source:

1. Create new file in `apis/` directory
2. Inherit from `BaseAPIClient`
3. Implement `analyze()` method
4. Add to `apis/__init__.py`
5. Update main app to display results
6. Add unit tests

## License

MIT License - See LICENSE file

## Disclaimer

This tool is for authorized security research and authorized penetration testing only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing systems you do not own.

## Support

For issues and questions:
- Create an issue on GitHub
- Check existing documentation
- Review API provider documentation

## References

- [VirusTotal API](https://developers.virustotal.com/)
- [Shodan API](https://shodan.io/docs)
- [AlienVault OTX](https://otx.alienvault.com/api/)
- [IPInfo API](https://ipinfo.io/docs)
- [AbuseIPDB API](https://docs.abuseipdb.com/)
- [URLhaus API](https://urlhaus-api.abuse.ch/)
