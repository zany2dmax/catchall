BINARY_NAME=wysescan

all: lint build
 
lint:
	staticcheck ./...

build:
	go build -o ${BINARY_NAME} main.go
	cp ${BINARY_NAME} ~/bin
 
run:
	go run  -o ${BINARY_NAME} main.go
 
clean:
	go clean
	rm ${BINARY_NAME}
