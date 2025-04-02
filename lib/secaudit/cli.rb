# lib/secaudit/cli.rb
require "thor"
require "uri"
require "zip"

require_relative "audit_runner"
require_relative "version"

module SecAudit
  class CLI < Thor
    desc "audit URL", "Run a security audit on the specified URL"
    option :output, aliases: "-o", type: :string, default: nil, desc: "Output directory (or full path if only one format)"
    option :format, aliases: "-f", type: :string, default: "markdown", desc: "Output format (markdown, json, html)"
    option :verbose, aliases: "-v", type: :boolean, default: false, desc: "Enable verbose logging"
    option :zip, type: :boolean, default: false, desc: "Compress the report into a .zip file"

    def audit(url)
      puts_banner
      SecAudit::LOGGER.level = Logger::DEBUG if options[:verbose]

      format = options[:format]
      uri = URI.parse(url)
      host = uri.host
      default_filename = "#{host}_security_audit.#{format}"

      output_path = if options[:output]
                      if options[:output].end_with?(".#{format}")
                        options[:output] # treat as full file path
                      else
                        File.join(options[:output], default_filename)
                      end
                    else
                      File.join("reports", default_filename)
                    end

      AuditRunner.new(url, File.dirname(output_path), [format]).run

      if options[:zip]
        zip_path = "#{output_path}.zip"
        begin
          File.delete(zip_path) if File.exist?(zip_path) # 💥 Remove existing zip first
          Zip::File.open(zip_path, Zip::File::CREATE) do |zipfile|
            zipfile.add(File.basename(output_path), output_path)
          end
          puts "✅ Report successfully compressed to #{zip_path}"
        rescue StandardError => e
          SecAudit::LOGGER.error("❌ Failed to compress the report: #{e.message}")
        end
      end
    end

    desc "version", "Show the version of SecAudit"
    def version
      puts "SecAudit version #{SecAudit::VERSION}"
    end

    no_commands do
      def puts_banner
        puts <<~BANNER

          ██████╗ ██╗  ██╗ █████╗ ███╗   ███╗████████╗ ██████╗ ██████╗ ███████╗ ██████╗ ███╗   ██╗
          ██╔══██╗██║  ██║██╔══██╗████╗ ████║╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝██╔═══██╗████╗  ██║
          ██████╔╝███████║███████║██╔████╔██║   ██║   ██║   ██║██████╔╝█████╗  ██║   ██║██╔██╗ ██║
          ██╔═══╝ ██╔══██║██╔══██║██║╚██╔╝██║   ██║   ██║   ██║██╔═══╝ ██╔══╝  ██║   ██║██║╚██╗██║
          ██║     ██║  ██║██║  ██║██║ ╚═╝ ██║   ██║   ╚██████╔╝██║     ███████╗╚██████╔╝██║ ╚████║
          ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝   ╚═╝    ╚═════╝ ╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝

                           🕯️  PhantomRecon Web Security Scanner v1.0 🕯️

        BANNER
      end
    end
  end
end
