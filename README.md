# PhantomRecon Web Security Scanner

-  PhantomRecon is a professional-grade, modular website security scanner designed to audit the security posture of web properties. 
-  It performs in-depth passive analysis of SSL/TLS certificates, HTTP security headers, and other security measures, generating actionable reports for website hardening.

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

**Clone the repository to your local machine:**

```
git clone [https://github.com/ifconfigme/phantom-recon.git]
```

## Dependencies

**Ensure you have Ruby installed (version 2.7 or higher is recommended).**

**Install the required gems:**
```
gem install thor
gem install zip
gem install dnsruby
gem install zip
gem install dnsruby
```

## Usage
-  Run a security audit for a target URL:
```
- ruby bin/secaudit audit <URL> -v --zip
```
- ```<URL>```: The target website to audit (e.g., https://example.com).
- ```-v```: Enable verbose logging.
- ```--zip```: Compress the output report into a .zip file.

**Example**
```
ruby bin/secaudit audit https://yahoo.com -v --zip
```

## Deployment

**This tool can be used locally or as part of a continuous integration pipeline (e.g., GitHub Actions, GitLab CI).**

## Project Structure

- Here's a quick overview of the project structure:
```
LICENSE
README.md
secaudit.gemspec
├───bin
│       secaudit
├───lib
│   │   secaudit.rb
│   │
│   └───secaudit
│           audit.rb
│           audit_runner.rb
│           cli.rb
│           version.rb
└───reports
```
### Example: GitHub Actions Configuration

- Create a `.github/workflows/security-audit.yml` file in your repository with the following content:

```
# .github/workflows/security-audit.yml

# This GitHub Actions workflow performs a security audit on the project.
# It checks out the code, sets up Ruby, runs a security audit script, and uploads the results.

name: Security Audit

on:
  schedule:
    - cron: "0 0 * * 1" # Every Monday at midnight UTC
  workflow_dispatch:

jobs:
  audit: # Defines a job named "audit"
    runs-on: ubuntu-latest # Specifies the runner environment (Ubuntu latest version)
    steps: # Steps to execute in the job
      - name: Checkout code
        uses: actions/checkout@v3 # Uses the GitHub-provided action to check out the repository code
        with:
          fetch-depth: 0 # Ensures the full history is fetched (useful for certain tools)

      - name: Set up Ruby
        uses: ruby/setup-ruby@v1 # Sets up the Ruby environment using the specified action
        with:
          ruby-version: "3.3" # Specifies the Ruby version to use (3.3 in this case)

      - name: Run Security Audit in Markdown, HTML, and JSON
        run: |
          mkdir -p reports # Creates a directory named "reports" to store the audit results
          ruby tools/security_audit.rb -u <"URL"> -o reports -f markdown,html,json
          # Runs the security audit script located in "tools/security_audit.rb"
          # -u: Specifies the URL to audit (replace <"URL"> with the actual URL)
          # -o: Specifies the output directory for the reports
          # -f: Specifies the output formats (Markdown, HTML, and JSON)

      - name: Upload audit reports
        uses: actions/upload-artifact@v4 # Uses the GitHub-provided action to upload artifacts
        with:
          name: security-audit-reports # Names the uploaded artifact "security-audit-reports"
          path: reports/ # Specifies the path to the reports directory
```

**For inquiries or issues, please create an issue on the GitHub repository or visit:**
- [GitHub Issues](https://github.com/ifconfigme/phantom-recon/issues)
