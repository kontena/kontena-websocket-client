#!/bin/sh

set -uex

DIR=$(dirname $0)
SERVER_ARGS=${SERVER_ARGS:- -drop}
BENCHMARK=${BENCHMARK:-benchmark-client.rb}

go get -d github.com/gorilla/websocket
go build -o $DIR/websocket-echo-server $DIR/websocket-echo-server.go

killall websocket-echo-server || true
$DIR/websocket-echo-server -quiet $SERVER_ARGS &

$DIR/${BENCHMARK}

trap "kill 0" INT EXIT
