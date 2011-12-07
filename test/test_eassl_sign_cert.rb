require 'helper'

class TestEasslSignCert < Test::Unit::TestCase
  def test_sign_csr
    
    csr_text = <<CSR
-----BEGIN CERTIFICATE REQUEST-----
MIIBhDCB7gIBADBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEh
MB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQC+RvNakUHlmlT3jMtkVx0Eajv6sxtzyk0qmSRKHU9/2q+1
3/jUM9fnc18hDBoI9PsObJc8CueXFnOVN9fyaQQXyr/mesvYgNn+XTSkE8HWiFSP
CMD3Sc8picEFEW5G/ZDrkqmygIY9E/kk9tQmWFolfIjWCTQPe/xh0f9kK/MkYwID
AQABoAAwDQYJKoZIhvcNAQEFBQADgYEAp5Bf2vGSzAB9uhWZ3bDPmAcvFDgXRSrk
3qlsOLDFy2uxHZxrJROo89YstwHMEDPHN2uNMpMaAfT2aiAVwQbjeu7/wQ5rnf35
LY18Mf/fqkFIqSolbHhaV3j1MvBMseAj3GidItX/HZiwzU2dSsb36o8KthkO5IX1
9R2JzARogT0=
-----END CERTIFICATE REQUEST-----
CSR
    
    ca = EaSSL::CertificateAuthority.load(:ca_path => 'test/CA', :ca_password => '1234')
    csr = EaSSL::SigningRequest.new(:csr => csr_text)
    cert = EaSSL::Certificate.new(:signing_request => csr, :ca_certificate => ca.certificate)
    cert.sign(ca.key)
    
    c = OpenSSL::X509::Certificate.new cert.to_pem
    assert c
    
    # subject from CSR text above
    assert_equal '/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd', c.subject.to_s

    # issuer from test CA
    assert_equal "/C=US/O=Venda/OU=auto-CA/CN=CA", c.issuer.to_s
  end
end
