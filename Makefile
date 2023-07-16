.PHONY: all format generate build

all: build

build:
	go build -o ./bin/nmon
