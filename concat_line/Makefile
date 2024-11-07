BINARY_NAME=cl

all: build test run
 
build:
	go build -o ${BINARY_NAME} cl.go
 
test:
	go test -v cl.go -i ips.txt
 
run:
	go build -o ${BINARY_NAME} cl.go
	./${BINARY_NAME}
 
clean:
	go clean
	rm ${BINARY_NAME}
