# 🕵️‍♂️ PhantomRecon — Modular Website Security Scanner
#
# A professional-grade auditing tool for evaluating the security posture
# of one or more web properties. Performs in-depth passive analysis and
# generates actionable reports for web hardening.
#
# 🔐 1. SSL/TLS Certificate Audit:
#    - Fetches and validates SSL certificates via HTTPS.
#    - Analyzes CN, issuer, validity range, days left, TLS version, cipher.
#
# 🛡️ 2. HTTP Security Headers & Cookies:
#    - Checks HTTP headers for standard protections (e.g., HSTS, CSP, XFO).
#    - Scores headers, flags missing ones, and inspects cookie flags.
#
# 🌐 3. DNS + CDN Fingerprinting:
#    - Detects CDN usage (Cloudflare, Akamai, Fastly, etc.)
#    - Performs DNSSEC verification and extracts CAA records.
#
# 📊 4. Reporting Engine:
#    - Outputs detailed results in Markdown, JSON, and HTML formats.
#    - Beautified HTML includes inline styling; Markdown supports CI logs.
#
# ⚙️ 5. CLI & Automation Friendly:
#    - Supports space/comma-separated URLs.
#    - Thread pool enables fast parallel scanning.
#    - Verbose logging option for debugging.
#    - GitHub Actions compatible.
#
# ▶ Usage:
#    ruby phantomrecon.rb -u <url1,url2,...> [-o output_dir] [-f format] [-t threads] [-v]
#
# ⚠️ Legal & Responsible Use Notice:
# This tool is provided for lawful, ethical use only. It is intended for security audits,
# compliance verification, and hardening of *your own* web infrastructure, or systems
# for which you have *explicit authorization*.
#
# Unauthorized scanning, probing, or intrusion of systems you do not own or manage
# may violate civil and criminal statutes including (but not limited to):
#
# - The Computer Fraud and Abuse Act (CFAA): https://www.law.cornell.edu/uscode/text/18/1030
# - Electronic Communications Privacy Act (ECPA): https://www.law.cornell.edu/uscode/text/18/2510
# - State-level cybersecurity laws (e.g., California Penal Code § 502)
#
# Violations may result in fines, termination of services, or prosecution. The author
# assumes no liability for misuse of this tool. You are solely responsible for
# your actions and ensuring they are compliant with applicable laws and regulations.
#
# Author: Daniel J. Monbrod
# License: MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
#!/usr/bin/env ruby

require 'cgi'
require 'net/http'
require 'uri'
require 'openssl'
require 'date'
require 'logger'
require 'optparse'
require 'fileutils'
require 'json'
require 'shellwords'
require 'thread'
require 'resolv'
require 'concurrent'

# Sanitize table values to avoid broken formatting
def sanitize_table_value(value)
  CGI.escapeHTML(value.to_s.strip.gsub(/([`*_{}\[\]()#+\-!|])/, '\\1'))
end

module HttpUtils
  def self.create_http(uri)
    http = Net::HTTP.new(uri.host, uri.port)
    if uri.scheme == "https"
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    end
    http
  end
end

module SecAudit
  LOGGER = Logger.new($stdout)
  MISSING_HEADER_VALUE = "MISSING"
  SSL_EXPIRATION_WARNING_THRESHOLD = 30

  def self.calculate_days_left(cert)
    ((cert.not_after - Time.now) / 86400).to_i
  end

  RECOMMENDED_HEADERS = {
    'Strict-Transport-Security' => 'max-age=63072000; includeSubDomains; preload',
    'Content-Security-Policy' => "default-src 'self'; script-src 'self' 'unsafe-inline'",
    'X-Frame-Options' => 'DENY',
    'X-Content-Type-Options' => 'nosniff',
    'Referrer-Policy' => 'strict-origin-when-cross-origin',
    'Permissions-Policy' => 'geolocation=(), microphone=()'
  }

  def self.resolve_dns_info(domain)
    results = { dnssec: "Unknown", caa: [] }
  
    begin
      require 'dnsruby'
      resolver = Dnsruby::Resolver.new
      response = resolver.query(domain, Dnsruby::Types::RRSIG)
      results[:dnssec] = response.answer.any?
  
      caa_query = resolver.query(domain, Dnsruby::Types::CAA)
      results[:caa] = caa_query.answer.map(&:value)
    rescue LoadError
      SecAudit::LOGGER.warn("Optional: Install 'dnsruby' gem to enable DNSSEC/CAA checks")
    rescue => e
      SecAudit::LOGGER.warn("DNS check failed: #{e.message}")
    end
  
    results
  end  

  def self.detect_cdn(uri)
    return 'Invalid URL' unless uri.is_a?(URI::HTTP) && uri.host

    begin
      response = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https') do |http|
        http.head('/')
      end
      headers = response.to_hash
      known_cdns = %w[cloudflare akamai fastly edgecast amazon]
      cdn = known_cdns.find { |name| headers.any? { |_, v| v.join.downcase.include?(name) } }
      cdn ? cdn.capitalize : 'Unknown or None'
    rescue SocketError
      SecAudit::LOGGER.warn("CDN detection failed: Host unreachable for #{uri.host}")
      'Host Unreachable'
    rescue => e
      SecAudit::LOGGER.warn("CDN detection failed: #{e.message}")
      'Error'
    end
  end

  class SSLChecker
    def initialize(url)
      begin
        parsed_url = URI.parse(url)
        @url = parsed_url.scheme ? url : "https://#{url}"
      rescue URI::InvalidURIError
        raise ArgumentError, "Invalid URL provided: #{url}"
      end
      @uri = URI.parse(@url)
    end

    def check
      result = {}
      begin
        http = HttpUtils.create_http(@uri)
        http.start do |connection|
          cert = connection.peer_cert
          result[:common_name] = cert.subject.to_a.find { |name, _, _| name == 'CN' }&.[](1) || "Unknown"
          result[:issuer] = cert.issuer.to_s
          result[:not_before] = cert.not_before
          result[:not_after] = cert.not_after
          result[:days_left] = SecAudit.calculate_days_left(cert)
          result[:valid] = cert.not_before <= Time.now && cert.not_after >= Time.now
          result[:ssl_version] = connection.respond_to?(:ssl_version) ? connection.ssl_version : "N/A"
          result[:cipher] = connection.respond_to?(:cipher) ? connection.cipher[0] : "N/A"
        end
      rescue => e
        result[:error] = "SSL check failed: #{e.message}"
      end
      result
    end
  end

  class HeaderChecker
    def initialize(url)
      begin
        @url = URI.parse(url).scheme ? url : "http://#{url}"
        @uri = URI.parse(@url)
      rescue URI::InvalidURIError => e
        raise ArgumentError, "Invalid URL provided: #{url}. Error: #{e.message}"
      end
    end

    def check
      result = { headers: {}, score: 0, max_score: RECOMMENDED_HEADERS.size }
      begin
        http = HttpUtils.create_http(@uri)
        response = http.head(@uri.path.empty? ? '/' : @uri.path)
        headers = response.to_hash.transform_keys(&:downcase)
        RECOMMENDED_HEADERS.each do |header, _|
          normalized_header = header.downcase
          header_value = headers[normalized_header]&.join(", ")
          value = header_value || MISSING_HEADER_VALUE
          result[:headers][header] = value
          result[:score] += 1 if header_value
        end
        parse_cookies(response, result)
      rescue => e
        result[:error] = "Header check failed: #{e.message}"
      end
      result
    end

    def parse_cookies(response, result)
      cookie = response['set-cookie']
      result[:set_cookie] = cookie || MISSING_HEADER_VALUE
      result[:cookie_secure] = cookie&.include?("Secure") ? "Yes" : "No"
      result[:cookie_httponly] = cookie&.include?("HttpOnly") ? "Yes" : "No"
    end
  end

  class ReportGenerator
    def initialize(ssl_result, header_result, target_url, formats)
      @ssl_result = ssl_result
      @header_result = header_result
      @target_url = target_url
      @formats = Array(formats)
    end

    def generate
      reports = {}
      @formats.each do |format|
        case format
        when "markdown"
          reports["markdown"] = generate_markdown
        when "json"
          reports["json"] = generate_json
        when "html"
          reports["html"] = generate_html
        else
          raise ArgumentError, "Unsupported format: #{format}"
        end
      end
      reports
    end

    def generate_markdown
      md = "# Security Audit Report\n"
      md << "**Target URL:** #{@target_url}\n"
      md << "**Generated on:** #{Time.now.utc}\n\n"
      md << "## 1. SSL Certificate Check\n\n"
      if @ssl_result[:error]
        md << "- **Error:** #{@ssl_result[:error]}\n"
      else
        dns_info = @ssl_result[:dns] || {}
        md << "- **Common Name (CN):** #{@ssl_result[:common_name]}\n"
        md << "- **Issuer:** #{@ssl_result[:issuer]}\n"
        md << "- **Valid From:** #{@ssl_result[:not_before]}\n"
        md << "- **Expires On:** #{@ssl_result[:not_after]}\n"
        md << "- **Days Until Expiration:** #{@ssl_result[:days_left]}\n"
        md << "- **SSL Version:** #{@ssl_result[:ssl_version]}\n"
        md << "- **Cipher:** #{@ssl_result[:cipher]}\n"
        md << "- **CDN:** #{@ssl_result[:cdn]}\n"
        md << "- **DNSSEC Enabled:** #{dns_info[:dnssec] ? 'Yes' : 'No'}\n"
        md << "- **CAA Records:** #{dns_info[:caa]&.join(', ') || 'None'}\n"
      end

      md << "\n## 2. Security Header Check\n\n"
      if @header_result[:error]
        md << "- **Error:** #{@header_result[:error]}\n"
      else
        md << "- **Security Header Score:** #{@header_result[:score]}/#{@header_result[:max_score]}\n\n"
        md << "| Header | Value |\n"
        md << "|--------|--------|\n"
        @header_result[:headers].each do |header, value|
          value = value.to_s.lines.first.strip if value.to_s.include?("\n")
          md << "| #{sanitize_table_value(header)} | #{sanitize_table_value(value)} |\n"
        end
      end

      md
    end

    def generate_json
      {
        target_url: @target_url,
        generated_on: Time.now.utc,
        ssl: @ssl_result,
        headers: @header_result
      }.to_json
    end

    def generate_html
      html = <<~HTML
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="UTF-8">
          <title>Security Audit Report</title>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; padding: 20px; }
            table { border-collapse: collapse; width: 100%; margin-top: 20px; }
            th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
            th { background-color: #f5f5f5; }
          </style>
        </head>
        <body>
          <h1>Security Audit Report</h1>
          <p><strong>Target URL:</strong> #{@target_url}</p>
          <p><strong>Generated on:</strong> #{Time.now.utc}</p>
      HTML

      if @ssl_result[:error]
        html << "<p><strong>SSL Error:</strong> #{@ssl_result[:error]}</p>"
      else
        html << "<h2>SSL Certificate Check</h2><ul>"
        @ssl_result.each { |k, v| html << "<li><strong>#{k.to_s.gsub('_', ' ').capitalize}:</strong> #{v}</li>" }
        html << "</ul>"
      end

      if @header_result[:error]
        html << "<p><strong>Header Check Error:</strong> #{@header_result[:error]}</p>"
      else
        html << "<h2>Security Headers</h2><table><tr><th>Header</th><th>Value</th></tr>"
        @header_result[:headers].each do |header, value|
          html << "<tr><td>#{sanitize_table_value(header)}</td><td>#{sanitize_table_value(value)}</td></tr>"
        end
        html << "</table>"
      end

      html << "</body></html>"
      html
    end
  end

  class AuditRunner
    def initialize(target_url, output_dir, formats)
      @target_url = target_url
      @output_dir = output_dir
      @formats = formats
    end

    def run
      SecAudit::LOGGER.info("Auditing #{@target_url}...")
      ssl_checker = SecAudit::SSLChecker.new(@target_url)
      ssl_result = ssl_checker.check
      uri = URI.parse(@target_url)
      ssl_result[:cdn] = SecAudit.detect_cdn(uri)
      ssl_result[:dns] = SecAudit.resolve_dns_info(uri.host)      
      header_result = SecAudit::HeaderChecker.new(@target_url).check
      reports = SecAudit::ReportGenerator.new(ssl_result, header_result, @target_url, @formats).generate
      host = uri.host

      @formats.each do |fmt|
        file_path = File.join(@output_dir, "#{host}_security_audit.#{fmt}")
        FileUtils.mkdir_p(File.dirname(file_path)) unless Dir.exist?(File.dirname(file_path))
        if File.writable?(File.dirname(file_path))
          begin
            File.write(file_path, reports[fmt])
            puts "✅ Report saved to #{file_path}"
          rescue Errno::EACCES
            SecAudit::LOGGER.error("Permission denied: Cannot write to #{file_path}")
          rescue => e
            SecAudit::LOGGER.error("Unexpected error while writing to #{file_path}: #{e.message}")
          end
        else
          SecAudit::LOGGER.error("Directory not writable: #{File.dirname(file_path)}")
        end
      end
    end
  end
end
