require 'helper'

class TestEasslCertificate < Test::Unit::TestCase

  def test_new_certificate_self_signed
    key  = EaSSL::Key.new
    name = EaSSL::CertificateName.new(:common_name => 'foo.bar.com')
    csr  = EaSSL::SigningRequest.new(:name => name, :key => key)

    cert = EaSSL::Certificate.new(:signing_request => csr)
    assert cert
    assert cert.ssl
    assert_equal cert.subject.to_s, csr.subject.to_s
    assert_equal cert.subject.to_s, cert.issuer.to_s
  end

  def test_certificate_to_pem
    key = EaSSL::Key.new
    name = EaSSL::CertificateName.new(:common_name => 'foo.bar.com')
    csr = EaSSL::SigningRequest.new(:name => name, :key => key)

    cert = EaSSL::Certificate.new(:signing_request => csr)
    assert cert.to_pem =~ /BEGIN CERTIFICATE/
  end

  def test_new_server_certificate_ca_signed
    ca_path = File.join(File.dirname(__FILE__), 'CA')
    ca = EaSSL::CertificateAuthority.load(:ca_path => ca_path, :ca_password => '1234')
    key = EaSSL::Key.new
    name = EaSSL::CertificateName.new(:common_name => 'foo.bar.com')
    csr = EaSSL::SigningRequest.new(:name => name, :key => key)

    cert = EaSSL::Certificate.new(:signing_request => csr, :ca_certificate => ca.certificate)
    cert.sign(ca.key)
    assert cert.to_pem =~ /BEGIN CERTIFICATE/
    assert_equal cert.subject.to_s, csr.subject.to_s
    assert_equal cert.issuer.to_s, ca.certificate.subject.to_s
    ext_key_usage = cert.extensions.select {|e| e.oid == 'extendedKeyUsage' }
    assert_equal "TLS Web Server Authentication", ext_key_usage[0].value
  end

  def test_new_client_certificate_ca_signed
    ca_path = File.join(File.dirname(__FILE__), 'CA')
    ca = EaSSL::CertificateAuthority.load(:ca_path => ca_path, :ca_password => '1234')
    key = EaSSL::Key.new
    name = EaSSL::CertificateName.new(:common_name => 'foo.bar.com')
    csr = EaSSL::SigningRequest.new(:name => name, :key => key)

    cert = EaSSL::Certificate.new(:type => 'client', :signing_request => csr, :ca_certificate => ca.certificate)
    cert.sign(ca.key)
    assert cert.to_pem =~ /BEGIN CERTIFICATE/
    assert_equal cert.subject.to_s, csr.subject.to_s
    assert_equal cert.issuer.to_s, ca.certificate.subject.to_s
    ext_key_usage = cert.extensions.select {|e| e.oid == 'extendedKeyUsage' }
    assert_equal "TLS Web Client Authentication, E-mail Protection", ext_key_usage[0].value
  end

  def test_load_certificate_file
    file = File.join(File.dirname(__FILE__), 'certificate.pem')
    cert = EaSSL::Certificate.load(file)
    assert cert
    assert_equal "55:27:E8:46:50:03:39:F4:A3:24:3D:88:57:BA:67:5C:F1:E8:84:1D", cert.sha1_fingerprint
  end

  def test_load_certificate_text
    cert_text = <<CERT
-----BEGIN CERTIFICATE-----
MIIDzzCCAzigAwIBAgIBAjANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzEO
MAwGA1UECgwFVmVuZGExEDAOBgNVBAsMB2F1dG8tQ0ExCzAJBgNVBAMMAkNBMB4X
DTExMTIwNzE5MTIxN1oXDTE2MTIwNTE5MTIxN1owgakxCzAJBgNVBAYTAlVTMRcw
FQYDVQQIEw5Ob3J0aCBDYXJvbGluYTEWMBQGA1UEBxMNRnVxdWF5IFZhcmluYTEY
MBYGA1UECgwPV2ViUG93ZXIgRGVzaWduMRUwEwYDVQQLDAxXZWIgU2VjdXJpdHkx
FDASBgNVBAMMC2Zvby5iYXIuY29tMSIwIAYJKoZIhvcNAQkBDBNlYXNzbEBydWJ5
Zm9yZ2Uub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyqWgYizb
EaafCYheeaTCGLK4FOq42e2CavOComQlWXEGR2YHYOL/cPK9Lpc+f/4qxse8SChx
1maDuUh+iT+fNa/jqbBExmK7h914mXW2pcZCfbboND0Va9wLm63HsMVwY2FGDC9P
Qh5hviVfIoGVbC2ZDI1pt98pexPsSOSHn2ch1q4s/9pfICnWN+KsEyNJuBwlo24t
Eg+zvnVE9w3YzlSQ7NCgPFf1aX2VBWZi50gbAwoxoKyrtZFQ/tIrF6WtMxYTpfYq
LYWLMsb9+xZHkhEc+XvvipD6Y25tlyDWoFOR3sy0B5SZGoik9ZD1bTCWHdEtNRzG
cRoChZSCv9+LeQIDAQABo4HuMIHrMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgWgMB0G
A1UdDgQWBBT6dj30hJuziSwhPx9PnsTyGCi3BjATBgNVHSUEDDAKBggrBgEFBQcD
ATA3BglghkgBhvhCAQ0EKhYoUnVieS9PcGVuU1NML0VhU1NMIEdlbmVyYXRlZCBD
ZXJ0aWZpY2F0ZTBkBgNVHSMEXTBbgBT+n8Ml3oKlSBBaeaaDrWFS9THk5aFApD4w
PDELMAkGA1UEBhMCVVMxDjAMBgNVBAoMBVZlbmRhMRAwDgYDVQQLDAdhdXRvLUNB
MQswCQYDVQQDDAJDQYIBADANBgkqhkiG9w0BAQUFAAOBgQBjN8LEARLiWjxV0o6U
XSM4ubws0pAXya34TIAQnlDKEEssZ0i1IYyyqieCkdaH+n0wnhGLwGf21yyrqCLd
+nDavx/2EBrDcF0yE7aapzXcfeXZ2gZxkZycuwc8dKR6IEXLWrMYS7HKyT490G0R
XBbgCxQiIndLwRnNMavd+vx0Wg==
-----END CERTIFICATE-----
CERT
    cert = EaSSL::Certificate.new({}).load(cert_text)
    assert cert
    assert_equal "55:27:E8:46:50:03:39:F4:A3:24:3D:88:57:BA:67:5C:F1:E8:84:1D", cert.sha1_fingerprint
  end

  def test_load_nonexistent_file
    assert_raises Errno::ENOENT do
      key = EaSSL::Certificate.load('./foo')
    end
  end

  def test_load_bad_file
    file = File.join(File.dirname(__FILE__), '..', 'Rakefile')
    assert_raises RuntimeError do
      key = EaSSL::Certificate.load(file)
    end
  end

end
