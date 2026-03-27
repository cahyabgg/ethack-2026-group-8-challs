CC      := gcc
CFLAGS  := -O2 -D_FORTIFY_SOURCE=3 -fPIE -fstack-protector-all -fcf-protection=full -fstack-clash-protection -fno-delete-null-pointer-checks -fno-strict-overflow
LDFLAGS := -pie -Wl,-z,relro,-z,now
TARGET  := chall
SRC     := chall.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)