# PhantomRecon Web Security Scanner

# PhantomRecon is a professional-grade, modular website security scanner.

- Audits the security posture of web properties.
- Performs in-depth passive analysis of:
  - SSL/TLS certificates.
  - HTTP security headers.
  - Other security measures.
- Generates actionable reports for website hardening.

## Features

- **SSL/TLS Certificate Audit**
  - Fetches and validates SSL certificates via HTTPS.
  - Analyzes the Common Name (CN), issuer, validity period, TLS version, and cipher.
- **HTTP Security Headers & Cookies**
  - Outputs detailed results in **Markdown**, **JSON**, and **HTML** formats.
  - HTML output is formatted for readability with inline styling, and Markdown is optimized for CI logs.
- **DNS & CDN Fingerprinting**
  - Detects CDN usage (e.g., Cloudflare, Akamai, Fastly).
  - Performs DNSSEC verification and extracts CAA records.
- **Reporting Engine**

  - Outputs detailed results in **Markdown**, **JSON**, and **HTML** formats.
  - Beautified HTML includes inline styling, and Markdown is optimized for CI logs.

- **CLI & Automation Friendly**
  - Supports space/comma-separated URLs.
  - Multi-threaded scanning for faster results.
  - Verbose logging for debugging.
  - GitHub Actions compatible for CI/CD integration.

## Installation

### Step 1: Clone the Repository

- **Clone the repository to your local machine:**
  - git clone https://github.com/danielmonbrod/phantom-recon.git

## Dependencies

**Ensure you have Ruby installed (version 2.7 or higher is recommended).**

**Install the required gems:**

- gem install thor
- gem install zip
- gem install dnsruby
- gem install zip
- gem install dnsruby

## Usage

- ruby bin/secaudit audit <URL> -v --zip

  - `--zip`: Compresses the output report into a `.zip` file for easier sharing and storage.

- ruby bin/secaudit audit <URL> -v --zip

- <URL>: The target website to audit (e.g., https://example.com).
- -v: Enable verbose logging.
- --zip: Compress the output report into a .zip file.

**Example**

- ruby bin/secaudit audit https://yahoo.com -v --zip

## Deployment

**This tool can be used locally or as part of a continuous integration pipeline**

- (e.g., GitHub Actions, GitLab CI).

### Example: GitHub Actions Configuration

Create a `.github/workflows/security-audit.yml` file in your repository with the following content:
**For inquiries or issues, please create an issue on the GitHub repository or visit:**

- [GitHub Issues](https://github.com/danielmonbrod/phantom-recon/issues)
