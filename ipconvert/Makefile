BINARY_NAME=ipc

all: lint build run
 
lint:
	staticcheck ./...

build:
	go build -o ${BINARY_NAME} ipconvert.go
 
run:
	go build -o ${BINARY_NAME} ipconvert.go
	./${BINARY_NAME}
 
test:
	go run ipconvert.go -i ips.txt

clean:
	go clean
	rm ${BINARY_NAME}
