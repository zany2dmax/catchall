BINARY_NAME=azusers
SOURCE_NAME="main.go"

deploy: scan lint build
 
scan:
	staticcheck ${SOURCE_NAME}

lint:
	golangci-lint run --fast ${SOURCE_NAME}

build:
	go build -o ${BINARY_NAME} ${SOURCE_NAME}
	cp ${BINARY_NAME} ~/bin
 
run:
	go run -o ${BINARY_NAME} ${SOURCE_NAME}
 
clean:
	go clean
	rm ${BINARY_NAME}
	rm ~/bin/${BINARY_NAME}
