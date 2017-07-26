require 'logger'

LOG_LEVEL = ENV['LOG_LEVEL'] || Logger::WARN

$logger = Logger.new(STDERR)
$logger.level = LOG_LEVEL
$logger.progname = 'websocket-benchmark'

# @yield at given target interval
# @return after duration
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

# @yield [seq, message]
# @return [Hash] after duration
def benchmark_sender(rate: 1000, duration: 5.0, message_size: 1000)
  total_size = 0
  seq = 0

  padding = 'X'*(message_size - 16 - 16)

  stats = with_rate(rate, duration) do |t|
    message = '%15.6f %15d %s' % [t.to_f, seq, padding]

    yield message, seq

    total_size += message.length
    seq += 1
  end

  return stats.merge(
    bytes: total_size,
  )
end

class BenchmarkReader
  def initialize
    @count = 0
    @bytes = 0
    @latency_total = 0.0
  end

  def start
    @t_start = Time.now
  end

  # @param time [Time] Time.now
  # @param message [String]
  # @return [Integer, Float] seq, rtt
  def on_message(time, message)
    msg_time_s, msg_seq_s, padding = message.split(' ', 3)
    msg_t = msg_time_s.to_f
    msg_seq = msg_seq_s.to_i
    t = time.to_f

    @count += 1
    @bytes += message.length
    @latency_total += (t - msg_t)

    return msg_seq, t - msg_t
  end

  # @return [Hash]
  def stop
    @t_stop = Time.now
    seconds = @t_stop - @t_start

    return {
      time: seconds,
      count: @count,
      rate: @count / seconds,
      bytes: @bytes,
      bytes_rate: @bytes / seconds,
      latency_avg: @latency_total / @count,
    }
  end
end

URL = 'ws://localhost:8080/echo'
RATES = [1, 10, 100, 1000, 3000, 5000, 10000]
DURATION = 5.0
MESSAGE_SIZE = 1000

HEADER = '%5s  %6s/s %9s: send @ %9s/s (%6s%% %6s%%) read @ %9s/s (%6s%%) = %12s/s ~%9s'
FORMAT = '%5.2fs %6d/s %9d: send @ %9.2f/s (%6.2f%% %6.2f%%) read @ %9.2f/s (%6.2f%%) = %12s/s ~%9.6fs'

def to_si(val)
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

# @yield [url, **options]
# @yieldreturn [send_stats, read_stats]
def run_benchmark()
  url = ENV['URL'] || URL

  rates = (ENV['RATES']&.split&.map{|r| Integer(r)} || RATES)
  duration = (ENV['DURATION'] || DURATION).to_f
  message_size = (ENV['MESSAGE_SIZE'] || MESSAGE_SIZE).to_i

  puts HEADER % ['TIME ', 'RATE', 'COUNT', 'MESSAGES', 'UTIL', 'MISS', 'MESSAGES', 'DROP', 'BYTES', 'LATENCY']

  for rate in rates
    options = {
      rate: rate,
      duration: duration,
      message_size: message_size,
    }

    $logger.info "benchmark: #{url} #{options}"

    send_stats, read_stats = yield(url, **options)

    drop_ratio = 1.0 - read_stats[:count].to_f / send_stats[:count].to_f

    puts FORMAT % [
      duration, rate, send_stats[:count],
      send_stats[:rate], send_stats[:util] * 100.0, send_stats[:miss] * 100.0,
      read_stats[:rate], drop_ratio * 100.0, to_si(read_stats[:bytes_rate]), read_stats[:latency_avg],
    ]
  end
end
