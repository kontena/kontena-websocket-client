#!/bin/sh

set -uex

DIR=$(dirname $0)

go get -d github.com/gorilla/websocket
go build -o $DIR/websocket-echo-server $DIR/websocket-echo-server.go

killall websocket-echo-server || true
$DIR/websocket-echo-server -quiet -drop &
$DIR/websocket-benchmark.rb &

trap "kill 0" INT EXIT
wait
