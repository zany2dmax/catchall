BINARY_NAME=ipv

all: lint build
 
lint:
	staticcheck ./...

build:
	go build -o ${BINARY_NAME} ip_verify.go
	cp ${BINARY_NAME} ~/bin
 
run:
	go run  -o ${BINARY_NAME} ip_verify.go
 
clean:
	go clean
	rm ${BINARY_NAME}
