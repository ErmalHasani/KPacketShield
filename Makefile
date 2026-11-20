CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iinclude -Ideps/windivert/include -DWIN32_LEAN_AND_MEAN
LDFLAGS = -Ldeps/windivert/lib -lfwpuclnt -liphlpapi -lws2_32 -lshlwapi -lshell32 -lWinDivert

SRCS = src/main.c \
       src/wfp_engine.c \
       src/proc_map.c \
       src/monitor.c \
       src/rule_store.c \
       src/ipc_pipe.c \
       src/service.c

OBJS = $(SRCS:.c=.o)
TARGET = bin/kpacketshield.exe
CLIENT_TARGET = bin/kps.exe

.PHONY: all clean copy_deps

all: $(TARGET) $(CLIENT_TARGET) copy_deps

$(TARGET): $(OBJS)
	@mkdir bin 2>NUL || true
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)
	@echo [OK] Built $(TARGET) successfully.

$(CLIENT_TARGET): src/kps_cli.c
	@mkdir bin 2>NUL || true
	$(CC) -Wall -Wextra -O2 src/kps_cli.c -o $(CLIENT_TARGET)
	@echo [OK] Built $(CLIENT_TARGET) successfully.

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

copy_deps:
	@copy deps\windivert\bin\WinDivert.dll bin\ >NUL 2>&1 || true
	@copy deps\windivert\bin\WinDivert64.sys bin\ >NUL 2>&1 || true

clean:
	@del /Q src\*.o bin\kpacketshield.exe 2>NUL || true
