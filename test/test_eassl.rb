require 'helper'

class TestEassl < Test::Unit::TestCase

  def test_generate_self_signed_defaults
    name = EaSSL::CertificateName.new(:common_name => 'foo.bar.com')
    ca, sr, cert = EaSSL.generate_self_signed(:name => name)

    assert ca
    assert_equal EaSSL::CertificateAuthority, ca.class
    assert_equal "/CN=CA", ca.certificate.subject.to_s

    assert sr
    assert_equal EaSSL::SigningRequest, sr.class
    assert_equal "/CN=foo.bar.com", sr.subject.to_s

    assert cert
    assert_equal EaSSL::Certificate, cert.class
    assert_equal "/CN=foo.bar.com", cert.subject.to_s

    key = sr.key
    assert key
    assert_equal EaSSL::Key, key.class
    assert_equal 2048, key.length
  end

  def test_config_webrick
    #webrick_config = {}
    #name = EaSSL::CertificateName.new(:common_name => 'foo.bar.com')
    #EaSSL.config_webrick(webrick_config, :name => name)
  end

end
