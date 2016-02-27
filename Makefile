BIN= pkt-capture
SRC= main.go

all:    $(SRC)
	go build $(BIN)
clean:
	rm $(BIN)
