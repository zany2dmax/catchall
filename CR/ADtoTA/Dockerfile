FROM golang:1.21

WORKDIR /app

COPY . .

RUN go mod init threataware && go mod tidy && go build -o threataware

CMD ["./threataware"]
