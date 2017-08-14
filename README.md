[![Build Status](https://travis-ci.org/kontena/kontena-websocket-client.svg?branch=master)](https://travis-ci.org/kontena/kontena-websocket-client)
[![Gem Version](https://badge.fury.io/rb/kontena-websocket-client.svg)](https://badge.fury.io/rb/kontena-websocket-client)
[![Yard Docs](http://img.shields.io/badge/yard-docs-blue.svg)](http://www.rubydoc.info/github/kontena/kontena-websocket-client/master)

# Kontena::Websocket::Client

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'kontena-websocket-client'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install kontena-websocket-client

## Usage

The high-level `Kontena::Websocket::Client#connect` API uses a synchronous programming model instead of the event-based `on(:event) do ...` model used by the browser WebSockets API:

* The `connect` class method yields the connected `Kontena::Websocket::Client` object
* The `read` method yields received websocket messages and returns once the websocket is closed
* The `send` and `close` methods can be called from the `connect` block, the `read` block, or a different thread
* Any of these functions can also raise `Kontena::Websocket::Error`

```ruby
require 'kontena-websocket-client'

def websocket_connect
  Kontena::Websocket::Client.connect(url, options...) do |client|
    on_open

    client.send(...)
    client.close(1000)

    client.read do |message|
      on_message(message)
    end

    on_close(client.close_code, client.close_reason) # client closed connection
  end
rescue Kontena::Websocket::CloseError => exc
  on_close(exc.code, exc.reason) # server closed connection
rescue Kontena::Websocket::Error => exc
  on_error(exc)
end
```
### Environment variables

The library uses the following environment variables:

* `SSL_CERT_FILE`: Default value for `ssl_params: { ca_file: ... }`
* `SSL_CERT_PATH`: Default value for `ssl_params: { ca_path: ... }`

### Threadsafe

The `Kontena::Websocket::Client` is threadsafe: while a single read thread is blocking on `read`, other threads may safely call `send`, `ping` and `close`.

The `read` block may also call `send`, `ping` and `close`.
Do not call `read` from multiple threads, or the websocket messages may get corrupted.

The library uses an internal `Mutex` to protect the internal `Websocket::Driver` state, and prevent socket read/write reordering/corruption.

XXX: The `on_pong` callback is called with the mutex held; do not call any client methods from the `on_pong` block.

### Timeouts

The `Kontena::Websocket::Client` uses timeouts (given in `options`) to deal with network errors and not leave the client hanging. Timeouts will raise a descriptive `Kontena::Websocket::TimeoutError` from either the `connect`, `read` or `send/close` methods.

* `connect_timeout` is used for both TCP, SSL `connect` operations
* `open_timeout` is used for the websocket `open` handshake
* `write_timeout` is used for each socket `write` operation
* `ping_timeout` is used for each websocket `ping` request

The `Kontena::Websocket::Client` supports keepalive pings, where the `read` method will send a websocket ping request every `ping_interval` seconds, and raise a `Kontena::Websocket::TimeoutError` if it does not receive a websocket pong response within `ping_timeout` seconds.

### SSL Validation

The `Kontena::Websocket::Client` validates `wss://` server SSL certificates by default, using the OpenSSL APIs to provide useful `Kontena::Websocket::SSLVerifyError` messages. It also provides methods to inspect and validate the server SSL certificates, even when not using strict SSL validation.

Example code and resulting messages:

```ruby
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
```

* `ERROR -- websocket-echo-client: certificate verify failed: self signed certificate`
* `WARN -- websocket-echo-client: Connected to wss://localhost:9293 with ssl errors: certificate verify failed: self signed certificate (subject /CN=kontena.test, issuer /CN=kontena.test)`
* `WARN -- websocket-echo-client: Connected to wss://echo.websocket.org without ssl verify: /OU=Domain Control Validated/CN=*.websocket.org (issuer /C=US/ST=Arizona/L=Scottsdale/O=GoDaddy.com, Inc./OU=http://certs.godaddy.com/repository//CN=Go Daddy Secure Certificate Authority - G2)`
* `INFO -- websocket-echo-client: Connected to wss://echo.websocket.org with ssl verify: /OU=Domain Control Validated/CN=*.websocket.org (issuer /C=US/ST=Arizona/L=Scottsdale/O=GoDaddy.com, Inc./OU=http://certs.godaddy.com/repository//CN=Go Daddy Secure Certificate Authority - G2)`
* `INFO -- websocket-echo-client: Connected to ws://echo.websocket.org without ssl`

### Examples

Use `bundle exec ./examples/...` to run the examples.

#### [Websocket Echo Client](./examples/websocket-echo-client.rb)

Connect to a websocket server, displaying the server SSL certificate. Send lines from `stdin`, and write messages to `stdout`. Close on `EOF`.

```
I, [2017-07-21T17:06:48.353944 #17507]  INFO -- : Connecting to wss://echo.websocket.org...
I, [2017-07-21T17:06:49.329616 #17507]  INFO -- : Connected to wss://echo.websocket.org with ssl verify: /OU=Domain Control Validated/CN=*.websocket.org (issuer /C=US/ST=Arizona/L=Scottsdale/O=GoDaddy.com, Inc./OU=http://certs.godaddy.com/repository//CN=Go Daddy Secure Certificate Authority - G2)
hello
D, [2017-07-21T17:06:50.447423 #17507] DEBUG -- : websocket write: "hello\n"
D, [2017-07-21T17:06:50.578683 #17507] DEBUG -- : websocket read: "hello\n"
hello
D, [2017-07-21T17:06:51.135395 #17507] DEBUG -- : websocket close: EOF
I, [2017-07-21T17:06:51.375279 #17507]  INFO -- : Client closed connection with code 1000: EOF
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/kontena/kontena-websocket-client.
