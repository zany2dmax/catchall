BINARY_NAME=qag
CODEFILE=QAPIAssetgroups.go

all: lint build run
 
lint:
	staticcheck ./${CODEFILE}

build:
	go build -o ${BINARY_NAME} ${CODEFILE}
 
run:
	go build -o ${BINARY_NAME} ${CODEFILE}
	./${BINARY_NAME}
 
clean:
	go clean
	rm ${BINARY_NAME}
