#!/usr/bin/env ruby

require 'logger'
require 'kontena-websocket-client'

$logger = Logger.new(STDERR)
$logger.progname = 'websocket-echo-client'

def websocket_echo_writer(ws)
  while line = $stdin.gets
    $logger.debug "websocket write: #{line.inspect}"
    ws.send(line)
  end
  $logger.debug "websocket close: EOF"

  ws.close(1000, "EOF")
end

def websocket_echo_reader(ws)
  ws.read do |msg|
    $logger.debug "websocket read: #{msg.inspect}"
    $stderr.puts msg
  end
end

def websocket_echo_client(url, **options)
  write_thread = nil

  $logger.info "Connecting to #{url}..."

  Kontena::Websocket::Client.connect(url, **options) do |ws|
    begin
      ssl_cert = ws.ssl_cert!
    rescue Kontena::Websocket::SSLVerifyError => ssl_error
      ssl_cert = ssl_error.cert
    else
      ssl_error = nil
    end

    if ssl_cert && ssl_error
      $logger.warn "Connected to #{url} with ssl errors: #{ssl_error} (subject #{ssl_cert.subject}, issuer #{ssl_cert.issuer})"
    elsif ssl_error
      $logger.warn "Connected to #{url} with ssl errors: #{ssl_error}"
    elsif ssl_cert && !ws.ssl_verify?
      $logger.warn "Connected to #{url} without ssl verify: #{ssl_cert.subject} (issuer #{ssl_cert.issuer})"
    elsif ssl_cert
      $logger.info "Connected to #{url} with ssl verify: #{ssl_cert.subject} (issuer #{ssl_cert.issuer})"
    else
      $logger.info "Connected to #{url} without ssl"
    end

    write_thread = Thread.new {
      websocket_echo_writer(ws)
    }

    websocket_echo_reader(ws)

    $logger.info "Client closed connection with code #{ws.close_code}: #{ws.close_reason}"
  end

rescue Kontena::Websocket::CloseError => exc
  $logger.info "#{exc}"
rescue Kontena::Websocket::Error => exc
  $logger.error "#{exc}"
ensure
  if write_thread
    write_thread.kill
    write_thread.join
  end
end

url = ARGV[0] || ENV['WEBSOCKET_URL'] || 'wss://echo.websocket.org'
ssl_verify = ENV['WEBSOCKET_SSL_VERIFY']
ssl_verify = !ssl_verify.nil? && !ssl_verify.empty?

websocket_echo_client(url,
  ssl_params: {
    verify_mode: ssl_verify ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE,
  },
)
