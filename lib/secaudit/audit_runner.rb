# lib/secaudit/audit_runner.rb
require "uri"
require "fileutils"
require_relative "audit"

module SecAudit
  class AuditRunner
    def initialize(target_url, output_dir, formats)
      @target_url = target_url
      @output_dir = output_dir
      @formats = Array(formats)
    end

    def run
      SecAudit::LOGGER.info("Auditing #{@target_url}...")
    
      ssl_checker = SecAudit::SSLChecker.new(@target_url)
      ssl_result = ssl_checker.check
    
      uri = URI.parse(@target_url)
      ssl_result[:cdn] = SecAudit.detect_cdn(uri)
      ssl_result[:dns] = SecAudit.resolve_dns_info(uri.host)
    
      header_result = SecAudit::HeaderChecker.new(@target_url).check
    
      reports = SecAudit::ReportGenerator.new(
        ssl_result,
        header_result,
        @target_url,
        @formats
      ).generate
    
      # Ensure the output directory exists and is not a file
      if File.exist?(@output_dir) && !File.directory?(@output_dir)
        SecAudit::LOGGER.error("❌ '#{@output_dir}' exists and is not a directory.")
        return
      end
      FileUtils.mkdir_p(@output_dir) unless Dir.exist?(@output_dir)
    
      host = uri.host
    
      @formats.each do |fmt|
        file_path = File.join(@output_dir, "#{host}_security_audit.#{fmt}")
    
        if File.writable?(@output_dir)
          begin
            File.write(file_path, reports[fmt])
            puts "✅ Report saved to #{file_path}"
          rescue Errno::EACCES
            SecAudit::LOGGER.error("Permission denied: Cannot write to #{file_path}")
          rescue => e
            SecAudit::LOGGER.error("Unexpected error while writing to #{file_path}: #{e.message}")
          end
        else
          SecAudit::LOGGER.error("Directory not writable: #{@output_dir}")
        end
      end
    end
  end
end
