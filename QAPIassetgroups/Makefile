BINARY_NAME=qag
CODEFILE=QAPIAssetgroups.go

all: lint build run
 
lint:
	staticcheck ./${CODEFILE}

build:
	go build -o ${BINARY_NAME} ${CODEFILE}
	cp ${BINARY_NAME} ~/bin
 
run:
	go build -o ${BINARY_NAME} ${CODEFILE}
	./${BINARY_NAME}
 
clean:
	go clean
	rm ${BINARY_NAME} ~/bin/${BINARY_NAME}
