require 'openssl'
require 'eassl'
module EaSSL
  # Author::    Paul Nicholson  (mailto:paul@webpowerdesign.net)
  # Co-Author:: Adam Williams (mailto:adam@thewilliams.ws)
  # Copyright:: Copyright (c) 2006 WebPower Design
  # License::   Distributes under the same terms as Ruby
  class CertificateAuthority
    attr_reader :key, :certificate
    def initialize(options = {})
      if options[:key] && options[:certificate]
        @key = options[:key]
        @certificate = options[:certificate]
      else
        @key = Key.new({:password => 'ca_ssl_password'}.update(options))
        @certificate = AuthorityCertificate.new(:key => @key)
      end
    end

    def self.load(options)
      key = Key.load(File.join(options[:ca_path], 'cakey.pem'), options[:ca_password])
      certificate = AuthorityCertificate.load(File.join(options[:ca_path], 'cacert.pem'), :key => key)
      self.new(:key => key, :certificate => certificate)
    end

    def create_certificate(signing_request)
      cert = Certificate.new(:signing_request => signing_request, :ca_certificate => @certificate)
      cert.sign(@key)
      cert
    end
  end
end
