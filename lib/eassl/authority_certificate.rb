require 'openssl'
require 'eassl'
module EaSSL
  # Author::    Paul Nicholson  (mailto:paul@webpowerdesign.net)
  # Co-Author:: Adam Williams (mailto:adam@thewilliams.ws)
  # Copyright:: Copyright (c) 2006 WebPower Design
  # License::   Distributes under the same terms as Ruby
  class AuthorityCertificate
    def initialize(options)
      @options = {
        :key => nil, #required
        :name => {}, #required, CertificateName
      }.update(options)
    end

    def ssl
      unless @ssl
        cert = OpenSSL::X509::Certificate.new
        cert.not_before = Time.now
        cert.subject = cert.issuer = CertificateName.new({ :common_name => "CA" }.update(@options[:name])).name
        cert.not_after = cert.not_before + (365 * 5) * 24 * 60 * 60
        cert.public_key = @options[:key].public_key
        cert.serial = 1
        cert.version = 2 # X509v3

        ef = OpenSSL::X509::ExtensionFactory.new
        ef.subject_certificate = cert
        ef.issuer_certificate = cert
        cert.extensions = [
          ef.create_extension("basicConstraints","CA:TRUE"),
          ef.create_extension("keyUsage", "cRLSign, keyCertSign"),
          ef.create_extension("subjectKeyIdentifier", "hash"),
          ef.create_extension("nsComment", "Ruby/OpenSSL/EaSSL Generated Certificate"),
        ]
        cert.add_extension(ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always"))
        cert.sign(@options[:key].private_key, OpenSSL::Digest::SHA1.new)
        @ssl = cert
      end
      @ssl
    end

    def method_missing(method)
      ssl.send(method)
    end

    def load(pem_string)
      begin
        @ssl = OpenSSL::X509::Certificate.new(pem_string)
      rescue
        raise "CertificateLoader: Error loading certificate"
      end
      self
    end

    def self.load(pem_file_path)
      new({}).load(File.read(pem_file_path))
    end
  end
end
