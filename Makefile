.PHONY: all format generate build

all: build

build:
	go mod tidy
	go build -o ./bin/nperf
