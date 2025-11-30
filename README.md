# JS-SEC

```
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║   ▐▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▌     ║
    ║   ▐       ██╗███████╗      ███████╗███████╗ ██████╗         ▌     ║
    ║   ▐       ██║██╔════╝      ██╔════╝██╔════╝██╔════╝         ▌     ║
    ║   ▐       ██║███████╗█████╗███████╗█████╗  ██║              ▌     ║
    ║   ▐  ██   ██║╚════██║╚════╝╚════██║██╔══╝  ██║              ▌     ║
    ║   ▐  ╚█████╔╝███████║      ███████║███████╗╚██████╗         ▌     ║
    ║   ▐   ╚════╝ ╚══════╝      ╚══════╝╚══════╝ ╚═════╝         ▌     ║
    ║   ▐▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▌     ║
    ║                                                                   ║
    ║     ░▒▓ JavaScript Secret Scanner ▓▒░                             ║
    ║     Extract API keys, tokens & credentials from JS files          ║
    ║                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════╝
```

**Extract API keys, tokens & credentials from JavaScript files**

A fast, multi-threaded secret scanner designed for bug bounty hunters and security researchers. Scans JavaScript files for exposed API keys, tokens, credentials, and other sensitive data.

## Features

- **120+ Secret Patterns** - Comprehensive regex patterns for AWS, Google, GitHub, Slack, Stripe, OpenAI, and 50+ more services
- **Multi-threaded Scanning** - Concurrent URL processing with configurable worker threads
- **Minified JS Support** - Patterns optimized for bundled/minified JavaScript
- **Auto-save Results** - Automatic JSON output with batch saving for large scans
- **Low False Positives** - Precision patterns with prefix-based detection

## Installation

```bash
git clone https://github.com/buggedout-1/js-secrets.git
cd js-secrets
pip install -r requirements.txt
```

## Usage

```bash
python js-secrets.py -l urls.txt -p patterns.txt -w 12
```

### Arguments

| Argument | Description |
|----------|-------------|
| `-l, --list` | Path to file containing list of URLs |
| `-p, --patterns` | Path to patterns file (required) |
| `-w, --workers` | Number of threads (default: 8) |

### Output

Results are automatically saved to `secrets.json` in the following format:

```json
[
    {
        "url": "https://example.com/app.js",
        "secrets": {
            "AWS Access Key ID": ["AKIAIOSFODNN7EXAMPLE"],
            "Slack Bot Token": ["xoxb-123456789012-123456789012-abc123"]
        }
    }
]
```

## Pattern Categories

| Category | Services |
|----------|----------|
| **Cloud** | AWS, Google/GCP, Azure, DigitalOcean, Heroku |
| **Git/VCS** | GitHub, GitLab, Bitbucket |
| **Communication** | Slack, Discord, Telegram, Twilio, SendGrid |
| **Payment** | Stripe, PayPal, Square, Braintree, Coinbase |
| **AI Services** | OpenAI, Anthropic |
| **Databases** | MongoDB, PostgreSQL, MySQL, Redis |
| **DevOps** | Vault, Doppler, CircleCI, Jenkins, SonarQube |
| **Analytics** | Datadog, New Relic, Sentry, Mixpanel, Amplitude |
| **SaaS** | Shopify, Salesforce, HubSpot, Zendesk, Airtable |
| **Auth** | Okta, Auth0, JWT, OAuth tokens |

## Best Usage

Combine with waybackurls for comprehensive scanning:

```bash
echo example.com | waybackurls | grep "\.js" | tee urls.txt
python js-secrets.py -l urls.txt -p patterns.txt -w 12
```

Or with gau:

```bash
gau example.com | grep "\.js" | tee urls.txt
python js-secrets.py -l urls.txt -p patterns.txt -w 12
```

## Screenshot

![JS-SEC Scanner](https://github.com/user-attachments/assets/2c056294-60a9-4336-a6eb-74c60d306dbb)

## Author

**buggedout**

- GitHub: [github.com/buggedout-1/js-secrets](https://github.com/buggedout-1/js-secrets)
- Version: 2.0

## License

This project is for educational and authorized security testing purposes only.



