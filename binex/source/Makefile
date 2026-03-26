CC      := gcc
CFLAGS  := -O2 -D_FORTIFY_SOURCE=2 -fPIE -fstack-protector-all
LDFLAGS := -pie -Wl,-z,relro,-z,now
TARGET  := chall
SRC     := chall.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)