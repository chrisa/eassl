require 'helper'

class TestEasslKey < Test::Unit::TestCase

  def test_new_keys_ssl
    key = EaSSL::Key.new
    assert key.ssl
    assert_equal OpenSSL::PKey::RSA, key.ssl.class
  end

  def test_new_keys_private_key
    key = EaSSL::Key.new
    assert key.private_key
    assert_equal OpenSSL::PKey::RSA, key.private_key.class
  end

  def test_new_key_defaults_bit_length
    key = EaSSL::Key.new
    assert_equal 2048, key.length
  end

  def test_new_key_defaults_password
    key = EaSSL::Key.new
    enckey = key.to_pem
    key2 = OpenSSL::PKey::RSA::new(enckey, 'ssl_password')
    assert_equal key2.to_s, key.ssl.to_s
  end

  def test_override_bit_length
    key = EaSSL::Key.new(:bits => 1024)
    assert_equal 1024, key.length
  end

  def test_override_password
    key = EaSSL::Key.new(:password => 'xyzzy')
    enckey = key.to_pem
    key2 = OpenSSL::PKey::RSA::new(enckey, 'xyzzy')
    assert_equal key2.to_s, key.ssl.to_s
  end

  def test_to_pem_string
    key = EaSSL::Key.new(:password => 'xyzzy')
    enckey = key.to_pem
    assert_equal String, enckey.class
    assert enckey =~ /BEGIN RSA PRIVATE KEY/
    assert enckey =~ /ENCRYPTED/
  end

  def test_load_encrypted_key_text
    key_text = <<KEY
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,95157FEDE26860DF

QtQcPFoYz58qBAE1BgrhZriIF8CFvMYgK5p92fSSHt9V2ySeEuBMwLJncp4tBJGG
IbjBVK9v4VB8NxrGoC7Qs/0JI5PkMVxwUIuzRC+KAXnImRaV258t+ydboYIwnsfl
2Do9eQonjPOWHvU1vWCQMXa/Jku9cqJnL3a7quZaGPHDW0ch/v2zPbF2LOFFJV8v
YvdYo7ml27+Zrr0rmnhF/XVtDwkQd/K0I3sXIr92fHk=
-----END RSA PRIVATE KEY-----
KEY
    key = EaSSL::Key.new.load(key_text, 'ssl_password')
    assert key
    assert_equal 256, key.length
  end

  def test_load_encrypted_key_file
    file = File.join(File.dirname(__FILE__), 'encrypted_key.pem')
    key = EaSSL::Key.load(file, 'ssl_password')
    assert key
    assert_equal 256, key.length
  end

  def test_load_unencrypted_key_text
    key_text = <<KEY
-----BEGIN RSA PRIVATE KEY-----
MIGsAgEAAiEAy57X7ZFkqicM+Nb9kOjCBs0Fz3dc3F3nhqx9cDnwHaMCAwEAAQIh
ALOYKsOzVaJuRxbEKWpCob5hIpOCJqwmdA9cFbrEv9zhAhEA/B/sb8dzCvaFM/p5
Bt6Y7QIRAM7AD/gt+xiWUH8z+ra7js8CEQCXelqkofFloc1P+GnkjbLVAhAriPXT
5JrDCqPYpTFd2RCxAhEA+WMGuSLXT3xK5XP/LHIiVg==
-----END RSA PRIVATE KEY-----
KEY
    key = EaSSL::Key.new.load(key_text)
    assert key
    assert_equal 256, key.length
  end

  def test_load_unencrypted_key_file
    file = File.join(File.dirname(__FILE__), 'unencrypted_key.pem')
    key = EaSSL::Key.load(file)
    assert key
    assert_equal 256, key.length
  end

  def test_load_nonexistent_file
    assert_raises Errno::ENOENT do
      key = EaSSL::Key.load('./foo')
    end
  end

  def test_load_bad_file
    file = File.join(File.dirname(__FILE__), '..', 'Rakefile')
    assert_raises RuntimeError do
      key = EaSSL::Key.load(file)
    end
  end
end
