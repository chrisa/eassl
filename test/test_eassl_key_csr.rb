require 'helper'

class TestEasslKeyCsr < Test::Unit::TestCase
  def test_generate_self_signed

    options = {
      :country => "GB",
      :state => "London",
      :city => "London",
      :organization => "Venda Ltd",
      :department => "Development",
      :email => "ssl@dev.venda.com",
      :common_name => "foo.dev.venda.com"
    }

    ea_key  = EaSSL::Key.new
    ea_name = EaSSL::CertificateName.new(options)
    ea_csr  = EaSSL::SigningRequest.new(:name => ea_name, :key => ea_key)

    csr = OpenSSL::X509::Request.new ea_csr.ssl.to_s
    assert csr

    assert_equal "/C=GB/ST=London/L=London/O=Venda Ltd/OU=Development/CN=foo.dev.venda.com/emailAddress=ssl@dev.venda.com", csr.subject.to_s

    key = OpenSSL::PKey::RSA.new ea_key.private_key.to_s
    assert key
  end
end

