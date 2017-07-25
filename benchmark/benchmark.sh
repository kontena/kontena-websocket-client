#!/bin/sh

set -uex

DIR=$(dirname $0)

go get -d github.com/gorilla/websocket
go build -o $DIR/websocket-echo-server $DIR/websocket-echo-server.go

$DIR/websocket-echo-server -quiet &
$DIR/websocket-benchmark.rb &

trap "kill 0" EXIT
wait
