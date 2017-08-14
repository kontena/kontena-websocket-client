class Kontena::Websocket::Client
  VERSION = "0.1.1"

  # Running ruby >= version?
  # @param gte_version [String]
  # @return [Boolean]
  def self.ruby_version?(gte_version)
    ruby_version = RUBY_VERSION.split('.').map{|x|x.to_i}
    gte_version = gte_version.split('.').map{|x|x.to_i}

    return (ruby_version <=> gte_version) >= 0
  end
end
