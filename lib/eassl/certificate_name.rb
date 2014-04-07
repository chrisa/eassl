require 'openssl'
require 'eassl'
module EaSSL
  # Author::    Paul Nicholson  (mailto:paul@webpowerdesign.net)
  # Co-Author:: Adam Williams (mailto:adam@thewilliams.ws)
  # Copyright:: Copyright (c) 2006 WebPower Design
  # License::   Distributes under the same terms as Ruby
  class CertificateName
    def initialize(options)
      @options = options
    end

    def ssl
      name_mapping = [
        ['C', :country, OpenSSL::ASN1::PRINTABLESTRING],
        ['ST', :state, OpenSSL::ASN1::PRINTABLESTRING],
        ['L', :city, OpenSSL::ASN1::PRINTABLESTRING],
        ['O', :organization, OpenSSL::ASN1::UTF8STRING],
        ['OU', :department, OpenSSL::ASN1::UTF8STRING],
        ['CN', :common_name, OpenSSL::ASN1::UTF8STRING],
        ['emailAddress', :email, OpenSSL::ASN1::IA5STRING]
      ]

      name = []
      name_mapping.each do |k|
        name << [k[0], @options[k[1]], k[2]] if @options[k[1]]
      end

      OpenSSL::X509::Name.new(name)
    end

    def name
      ssl
    end

    def options
      @options
    end
  end
end
