#!/usr/bin/env ruby

Thread.abort_on_exception = true

require 'faye/websocket'
require 'eventmachine'
require_relative './benchmark'

run_benchmark do |url, **options|
  send_thread = nil
  reader = BenchmarkReader.new

  EM.run {
    ws = Faye::WebSocket::Client.new(url)

    ws.on :open do |event|
      $logger.info "open"

      send_thread = Thread.new {
        send_stats = benchmark_sender(**options) do |msg|
          ws.send(msg)
        end

        ws.close()

        send_stats
      }

      reader.start()
    end

    ws.on :message do |event|
      reader.on_message(Time.now, event.data)
    end

    ws.on :close do |event|
      $logger.info "close"

      reader.stop
      EM.stop
    end

    ws.on :error do |event|
      $logger.warn "error: #{event}"

      exit 1
    end
  }

  read_stats = reader.stop()
  send_stats = send_thread.value

  next send_stats, read_stats
end
