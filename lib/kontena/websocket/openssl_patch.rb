require 'openssl'

class OpenSSL::SSL::SSLSocket
  def wait_readable(timeout)
    IO.select([self], nil, nil, timeout)
  end
  def wait_writable(timeout)
    IO.select(nil, [self], nil, timeout)
  end
end
