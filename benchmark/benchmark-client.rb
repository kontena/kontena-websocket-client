#!/usr/bin/env ruby

Thread.abort_on_exception = true

require 'kontena-websocket-client'
require_relative './benchmark'

WEBSOCKET_OPTIONS = {
  connect_timeout: 1.0,
  open_timeout: 1.0,
  ping_timeout: 1.0,
  ping_interval: nil,
  write_timeout: 5.0,
}

Kontena::Websocket::Logging.initialize_logger(STDERR, LOG_LEVEL)

run_benchmark do |url, **options|
  send_thread = nil
  reader = BenchmarkReader.new

  Kontena::Websocket::Client.connect(url, **WEBSOCKET_OPTIONS) do |client|
    $logger.info "connect: #{client}"

    send_thread = Thread.new {
      send_stats = benchmark_sender(**options) do |msg, seq|
        client.send(msg)
      end

      client.close()

      send_stats
    }

    reader.start()
    client.read do |message|
      reader.on_message(Time.now, message)
    end
  end

  read_stats = reader.stop()
  send_stats = send_thread.value

  next send_stats, read_stats
end
