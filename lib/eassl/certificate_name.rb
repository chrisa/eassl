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
        ['C', :country],
        ['ST', :state],
        ['L', :city],
        ['O', :organization],
        ['OU', :department],
        ['CN', :common_name],
        ['emailAddress', :email]
      ]

      name = []
      name_mapping.each do |k|
        name << [k[0], @options[k[1]], OpenSSL::ASN1::PRINTABLESTRING] if @options[k[1]]
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
