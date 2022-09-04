# A simple Makefile, to build run: make or make all 
TARGET	= gopost

# Linker flags, strip the bin
LFLAGS  = "-s -w"

SRCDIR	= cmd

SOURCES	:= $(wildcard $(SRCDIR)/*.go)

.PHONY: all run clean
all: ${TARGET}

$(TARGET): 
	go build -ldflags $(LFLAGS) -o $(SRCDIR)/$(TARGET) $(SOURCES)

run:
	go run $(SOURCES)

clean:
	@$ rm -f $(TARGET)

