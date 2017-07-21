require "bundler/setup"
require "kontena-websocket-client"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  config.before :all do
    Kontena::Websocket::Logging.initialize_logger(STDERR, (ENV['LOG_LEVEL'] || Logger::INFO).to_i)
  end
end
