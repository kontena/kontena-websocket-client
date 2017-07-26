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
        send_stats = benchmark_sender(**options) do |msg, seq|
          EM.next_tick {
            $logger.debug "send seq=%d" % [seq]
            ws.send(msg)
          }
        end

        EM.next_tick {
          $logger.info "close..."
          ws.close()
        }

        send_stats
      }

      reader.start()
    end

    read = 0

    ws.on :message do |event|
      seq, rtt = reader.on_message(Time.now, event.data)

      $logger.debug "read %d: seq=%d rtt=%.2f" % [read, seq, rtt]

      read += 1
    end

    ws.on :close do |event|
      $logger.info "closed"

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
