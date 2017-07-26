#!/usr/bin/env ruby

require 'logger'
require 'kontena-websocket-client'

Thread.abort_on_exception = true

log_level = ENV['LOG_LEVEL'] || Logger::WARN
WEBSOCKET_OPTIONS = {
  connect_timeout: 1.0,
  open_timeout: 1.0,
  ping_timeout: 1.0,
  ping_interval: nil,
  write_timeout: 5.0,
}

$logger = Logger.new(STDERR)
$logger.level = log_level
$logger.progname = 'websocket-benchmark'

Kontena::Websocket::Logging.initialize_logger(STDERR, log_level)

def with_rate(rate, duration, &block)
  t0 = Time.now
  interval = 1.0 / rate
  count = 0
  count_miss = 0
  total_yield = 0.0

  while (t = Time.now) < t0 + duration
    yield t

    t_yield = Time.now

    count += 1
    total_yield += (t_yield - t)

    t_next = t0 + count * interval

    if t_next > t_yield
      sleep t_next - t_yield
    else
      count_miss += 1
    end
  end

  t_total = t - t0

  return {
    time: t_total,
    count: count,
    rate: count / t_total,
    util: total_yield / t_total,
    miss: (count_miss / count),
  }
end

def websocket_benchark_sender(client, rate: 1000, duration: 5.0, message_size: 1000)
  total_size = 0

  padding = 'X'*(message_size - 15)

  stats = with_rate(rate, duration) do |t|
    client.send('%15.6f %s' % [t.to_f, padding])

    total_size += message_size
  end

  $logger.info "write close..."

  client.close()

  return stats.merge(
    bytes: total_size,
  )
end

def websocket_benchmark_reader(client)
  count = 0
  bytes = 0
  latency_total = 0.0

  client.read do |message|
    t = Time.now.to_f
    t_s, padding = message.split(' ', 2)
    t_f = t_s.to_f

    count += 1
    bytes += message.length
    latency_total += (t - t_f)
  end

  $logger.info "read done"

  return {
    count: count,
    bytes: bytes,
    latency_avg: latency_total / count,
  }
end

def websocket_benchmark(url, **options)
  send_thread = nil
  read_stats = nil

  Kontena::Websocket::Client.connect(url, **WEBSOCKET_OPTIONS) do |client|
    $logger.info "connect: #{client}"

    send_thread = Thread.new {
      websocket_benchark_sender(client, **options)
    }

    read_stats = websocket_benchmark_reader(client)
  end

  send_stats = send_thread.value

  return send_stats, read_stats
end

url = ENV['URL'] || 'ws://localhost:8080/echo'

RATES = [1, 10, 100, 1000, 3000, 5000, 10000]
rates = (ENV['RATES']&.split&.map{|r| Integer(r)} || RATES)
duration = (ENV['DURATION'] || 5.0).to_f
message_size = (ENV['MESSAGE_SIZE'] || 1000).to_i

HEADER = '%5s  %6s/s: send %9s @ %9s/s (%5s%% ~ %5s%%) recv %9s @ %12s/s ~ %9s'
FORMAT = '%5.2fs %6d/s: send %9d @ %9.2f/s (%5.2f%% ~ %5.2f%%) recv %9d @ %12s/s ~ %9.6fs'

def si(val)
  if val > 10**9
    '%.3fG' % [val / 10**9]
  elsif val > 10**6
    '%.3fM' % [val / 10**6]
  elsif val > 10**3
    '%.3fK' % [val / 10**3]
  else
    '%.3f ' % [val]
  end
end

puts HEADER % ['time ', 'rate', 'count', 'messages', 'util', 'miss', 'count', 'bytes', 'avg latency']

for rate in rates
  options = {
    rate: rate,
    duration: duration,
    message_size: message_size,
  }

  $logger.info "benchmark: #{url} #{options}"

  send_stats, read_stats = websocket_benchmark(url, **options)

  puts FORMAT % [
    duration, rate,
    send_stats[:count], send_stats[:rate], send_stats[:util] * 100.0, send_stats[:miss] * 100.0,
    read_stats[:count], si(read_stats[:bytes] / send_stats[:time]), read_stats[:latency_avg],
  ]
end
