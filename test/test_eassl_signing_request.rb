require 'helper'

class TestEasslSigningRequest < Test::Unit::TestCase

  def test_new_csr_gen_default_key
    name = EaSSL::CertificateName.new(:common_name => 'foo.bar.com')
    csr = EaSSL::SigningRequest.new(:name => name)
    assert csr
    assert_equal "/C=US/ST=North Carolina/L=Fuquay Varina/O=WebPower Design/OU=Web Security/CN=foo.bar.com/emailAddress=eassl@rubyforge.org", csr.subject.to_s
    assert csr.key
    assert_equal 2048, csr.key.length
  end

  def test_new_csr_specify_key
    file = File.join(File.dirname(__FILE__), 'unencrypted_key2.pem')
    key = EaSSL::Key.load(file)
    name = EaSSL::CertificateName.new(:common_name => 'foo.bar.com')
    csr = EaSSL::SigningRequest.new(:name => name, :key => key)
    assert csr
    assert_equal "/C=US/ST=North Carolina/L=Fuquay Varina/O=WebPower Design/OU=Web Security/CN=foo.bar.com/emailAddress=eassl@rubyforge.org", csr.subject.to_s
  end

  def test_load_csr_file
    file = File.join(File.dirname(__FILE__), 'csr.pem')
    csr = EaSSL::SigningRequest.load(file)
    assert csr
    assert_equal '/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd', csr.subject.to_s
  end

  def test_load_csr_text
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
    csr = EaSSL::SigningRequest.new.load(csr_text)
    assert csr
    assert_equal '/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd', csr.subject.to_s
  end

  def test_load_nonexistent_file
    assert_raises Errno::ENOENT do
      key = EaSSL::SigningRequest.load('./foo')
    end
  end

  def test_load_bad_file
    file = File.join(File.dirname(__FILE__), '..', 'Rakefile')
    assert_raises RuntimeError do
      key = EaSSL::SigningRequest.load(file)
    end
  end

end
