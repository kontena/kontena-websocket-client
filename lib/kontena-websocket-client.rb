require 'openssl'
require 'socket'
require 'websocket/driver'

# OpenSSL::SSL::SSLSocket#wait_readable, #wait_writable
require_relative './kontena/websocket/openssl_patch'

module Kontena
  module Websocket
    require_relative './kontena/websocket/client/version'
    require_relative './kontena/websocket/logging'
    require_relative './kontena/websocket/error'
    require_relative './kontena/websocket/client'
  end
end
