CC = gcc
LD = gcc
CINCLUDE =
CFLAGS = -Wall -g3 
COPTS = $(CFLAGS) $(CINCLUDE) $(CCPRAGMA)
LDLIBS = -lssl -lcrypto
LDOPTS = $(LDLIBS)

TARGET = ssl_proxy
OBJS = ssl_proxy.o

all: $(TARGET)

clean:
	rm -f $(TARGET) core *.o


$(TARGET): $(OBJS)
	$(LD) -o $@ $(OBJS) $(LDOPTS)

%.o: %.c
	$(CC) -c $(COPTS) $< -o $@
