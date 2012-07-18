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

  def test_new_ca_specified_name
    ca = EaSSL::CertificateAuthority.new(:name => {
      :country => 'GB',
      :state => 'London',
      :city => 'London',
      :organization => 'Venda Ltd',
      :department => 'Development',
      :common_name => 'CA',
      :email => 'dev@venda.com'
    })
    key = EaSSL::Key.new
    name = EaSSL::CertificateName.new(
      :country => 'GB',
      :state => 'London',
      :city => 'London',
      :organization => 'Venda Ltd',
      :department => 'Development',
      :common_name => 'foo.bar.com',
      :email => 'dev@venda.com'
    )
    csr = EaSSL::SigningRequest.new(:name => name, :key => key)
    cert = ca.create_certificate(csr)
    assert cert
    assert_equal "/C=GB/ST=London/L=London/O=Venda Ltd/OU=Development/CN=foo.bar.com/emailAddress=dev@venda.com", cert.subject.to_s
    assert_equal "/C=GB/ST=London/L=London/O=Venda Ltd/OU=Development/CN=CA/emailAddress=dev@venda.com", cert.issuer.to_s
    ext_key_usage = cert.extensions.select {|e| e.oid == 'extendedKeyUsage' }
    assert_equal "TLS Web Server Authentication", ext_key_usage[0].value
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
    ext_key_usage = cert.extensions.select {|e| e.oid == 'extendedKeyUsage' }
    assert_equal "TLS Web Server Authentication", ext_key_usage[0].value
  end

  def test_new_ca_sign_client_cert
    ca = EaSSL::CertificateAuthority.new
    key = EaSSL::Key.new
    name = EaSSL::CertificateName.new(:common_name => 'foo.bar.com')
    csr = EaSSL::SigningRequest.new(:name => name, :key => key)
    cert = ca.create_certificate(csr, 'client')
    assert cert
    assert_equal "/C=US/ST=North Carolina/L=Fuquay Varina/O=WebPower Design/OU=Web Security/CN=foo.bar.com/emailAddress=eassl@rubyforge.org", cert.subject.to_s
    assert_equal "/C=US/ST=North Carolina/L=Fuquay Varina/O=WebPower Design/OU=Web Security/CN=CA/emailAddress=eassl@rubyforge.org", cert.issuer.to_s
    ext_key_usage = cert.extensions.select {|e| e.oid == 'extendedKeyUsage' }
    assert_equal "TLS Web Client Authentication, E-mail Protection", ext_key_usage[0].value
  end

  def test_new_ca_sign_client_cert_with_expiry
    ca = EaSSL::CertificateAuthority.new
    key = EaSSL::Key.new
    name = EaSSL::CertificateName.new(:common_name => 'foo.bar.com')
    csr = EaSSL::SigningRequest.new(:name => name, :key => key)
    t = Time.now
    cert = ca.create_certificate(csr, 'client', 10)
    assert cert
    assert_equal "/C=US/ST=North Carolina/L=Fuquay Varina/O=WebPower Design/OU=Web Security/CN=foo.bar.com/emailAddress=eassl@rubyforge.org", cert.subject.to_s
    assert_equal "/C=US/ST=North Carolina/L=Fuquay Varina/O=WebPower Design/OU=Web Security/CN=CA/emailAddress=eassl@rubyforge.org", cert.issuer.to_s
    ext_key_usage = cert.extensions.select {|e| e.oid == 'extendedKeyUsage' }
    assert_equal "TLS Web Client Authentication, E-mail Protection", ext_key_usage[0].value
    assert_equal (t + (24 * 60 * 60 * 10)).to_i, cert.ssl.not_after.to_i
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
