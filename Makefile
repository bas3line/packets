# pktsniff - build system
#
#   make            build bin/pktsniff-server and bin/pktsniff-client
#   make test       build and run the unit tests (no root needed)
#   make asan       build with AddressSanitizer/UBSan into bin/asan/
#   make install    install into $(PREFIX)/bin (default /usr/local)
#   make clean
#
# libpcap is optional: with it, the server accepts tcpdump-style BPF filters
# (--filter). Without it the server still works and the client-side --filter is
# unaffected.

BIN      := bin
PREFIX   ?= /usr/local
CC       ?= cc
CSTD     := -std=c11
WARN     := -Wall -Wextra -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wvla -Wpointer-arith
OPT      ?= -O2 -g
CPPFLAGS += -D_GNU_SOURCE -Iinclude
CFLAGS   += $(CSTD) $(WARN) $(OPT) -fstack-protector-strong -fno-omit-frame-pointer
LDFLAGS  +=
LDLIBS   +=

PCAP_CFLAGS := $(shell pkg-config --cflags libpcap 2>/dev/null)
PCAP_LIBS   := $(shell pkg-config --libs libpcap 2>/dev/null)
ifeq ($(strip $(PCAP_LIBS)),)
  PCAP_LIBS := $(shell echo '-lpcap' | $(CC) -x c - -o /dev/null -lpcap >/dev/null 2>&1 && echo -lpcap)
endif
ifneq ($(strip $(PCAP_LIBS)),)
  CPPFLAGS += -DPS_HAVE_PCAP
  CFLAGS   += $(PCAP_CFLAGS)
  SERVER_LIBS += $(PCAP_LIBS)
endif

LIB_SRCS := src/log.c src/util.c src/stats.c src/proto.c src/decode.c src/filter.c \
            src/pcap.c src/outbuf.c
SERVER_SRCS := src/main_server.c src/server.c src/capture.c
CLIENT_SRCS := src/main_client.c src/client.c

LIB_OBJS    := $(LIB_SRCS:src/%.c=$(BIN)/obj/%.o)
SERVER_OBJS := $(SERVER_SRCS:src/%.c=$(BIN)/obj/%.o)
CLIENT_OBJS := $(CLIENT_SRCS:src/%.c=$(BIN)/obj/%.o)

PS_SERVER_BIN := pktsniff-server
PS_CLIENT_BIN := pktsniff-client
SERVER_BIN := $(BIN)/$(PS_SERVER_BIN)
CLIENT_BIN := $(BIN)/$(PS_CLIENT_BIN)

all: $(SERVER_BIN) $(CLIENT_BIN)

$(BIN)/obj/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

$(SERVER_BIN): $(LIB_OBJS) $(SERVER_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(SERVER_LIBS) $(LDLIBS)

$(CLIENT_BIN): $(LIB_OBJS) $(CLIENT_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

-include $(LIB_OBJS:.o=.d) $(SERVER_OBJS:.o=.d) $(CLIENT_OBJS:.o=.d)

# ---- tests ----
TEST_BIN := $(BIN)/tests
TEST_SRCS := $(wildcard tests/test_*.c)
TEST_PROGS := $(TEST_SRCS:tests/%.c=$(TEST_BIN)/%)

$(TEST_BIN)/%: tests/%.c $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc -o $@ $< $(LIB_OBJS) $(LDLIBS)

test: $(TEST_PROGS)
	@fail=0; for t in $(TEST_PROGS); do echo "== $$t"; ./$$t || fail=1; done; \
	 if [ $$fail -eq 0 ]; then echo "all tests passed"; else echo "TESTS FAILED"; exit 1; fi

# ---- sanitizer build ----
asan:
	$(MAKE) OPT='-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all' \
	        LDFLAGS='-fsanitize=address,undefined' BIN=bin/asan all test

install: all
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(SERVER_BIN) $(DESTDIR)$(PREFIX)/bin/$(PS_SERVER_BIN)
	install -m 0755 $(CLIENT_BIN) $(DESTDIR)$(PREFIX)/bin/$(PS_CLIENT_BIN)

install-service: all
	install -m 0644 packaging/pktsniff.service /etc/systemd/system/pktsniff.service
	systemctl daemon-reload
	@echo "edit /etc/pktsniff.conf then: systemctl enable --now pktsniff"

clean:
	rm -rf $(BIN)

distclean: clean
	rm -rf bin

print-config:
	@echo "CC           = $(CC)"
	@echo "libpcap      = $(if $(SERVER_LIBS),yes,no)"

.PHONY: all test asan install install-service clean distclean print-config
