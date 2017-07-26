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
        send = 0

        send_stats = benchmark_sender(**options) do |msg|
          send += 1
          $logger.debug "send %d" % send

          EM.next_tick {
            ws.send(msg)
          }
        end

        $logger.info "close..."

        EM.next_tick {
          ws.close()
        }

        send_stats
      }

      reader.start()
    end

    read = 0

    ws.on :message do |event|
      read += 1

      $logger.debug "read %d" % read

      reader.on_message(Time.now, event.data)
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
