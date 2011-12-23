require 'helper'

class TestEasslCertificateAuthority < Test::Unit::TestCase

  def test_new_ca
    ca = EaSSL::CertificateAuthority.new
    assert ca
    assert ca.key
    assert ca.certificate

    assert_equal 2048, ca.key.length
    assert_equal "/C=US/ST=North Carolina/L=Fuquay Varina/O=WebPower Design/OU=Web Security/CN=CA/emailAddress=eassl@rubyforge.org", ca.certificate.subject.to_s
  end

  def test_load_ca
    ca_path = File.join(File.dirname(__FILE__), 'CA')
    ca = EaSSL::CertificateAuthority.load(:ca_path => ca_path, :ca_password => '1234')
    assert ca
    assert ca.key
    assert ca.certificate

    assert_equal 1024, ca.key.length
    assert_equal "/C=US/O=Venda/OU=auto-CA/CN=CA", ca.certificate.subject.to_s
  end

  def test_new_ca_sign_cert
    ca = EaSSL::CertificateAuthority.new
    key = EaSSL::Key.new
    name = EaSSL::CertificateName.new(:common_name => 'foo.bar.com')
    csr = EaSSL::SigningRequest.new(:name => name, :key => key)
    cert = ca.create_certificate(csr)
    assert cert
    assert_equal "/C=US/ST=North Carolina/L=Fuquay Varina/O=WebPower Design/OU=Web Security/CN=foo.bar.com/emailAddress=eassl@rubyforge.org", cert.subject.to_s
    assert_equal "/C=US/ST=North Carolina/L=Fuquay Varina/O=WebPower Design/OU=Web Security/CN=CA/emailAddress=eassl@rubyforge.org", cert.issuer.to_s
  end

  def test_loaded_ca_sign_cert
    ca_path = File.join(File.dirname(__FILE__), 'CA')
    ca = EaSSL::CertificateAuthority.load(:ca_path => ca_path, :ca_password => '1234')
    key = EaSSL::Key.new
    name = EaSSL::CertificateName.new(:common_name => 'foo.bar.com')
    csr = EaSSL::SigningRequest.new(:name => name, :key => key)
    cert = ca.create_certificate(csr)
    assert cert
    assert_equal "/C=US/ST=North Carolina/L=Fuquay Varina/O=WebPower Design/OU=Web Security/CN=foo.bar.com/emailAddress=eassl@rubyforge.org", cert.subject.to_s
    assert_equal "/C=US/O=Venda/OU=auto-CA/CN=CA", cert.issuer.to_s
  end

  def test_loaded_ca_sign_certs_with_serial
    ca_path = File.join(File.dirname(__FILE__), 'CA')
    ca = EaSSL::CertificateAuthority.load(:ca_path => ca_path, :ca_password => '1234')

    next_serial = ca.serial.next

    key = EaSSL::Key.new
    name = EaSSL::CertificateName.new(:common_name => 'foo.bar.com')
    csr = EaSSL::SigningRequest.new(:name => name, :key => key)
    cert = ca.create_certificate(csr)
    assert cert
    assert cert.serial.to_i == next_serial
    assert ca.serial.next == next_serial + 1

    ca = EaSSL::CertificateAuthority.load(:ca_path => ca_path, :ca_password => '1234')
    assert ca.serial.next == next_serial + 1
  end

end
