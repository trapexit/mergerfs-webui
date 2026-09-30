# Copyright (c) 2026, Antonio SJ Musumeci <trapexit@spawn.link>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

CXXFLAGS ?= -std=c++17 -Wall -Wextra -Wpessimizing-move -Werror=pessimizing-move -Wredundant-move -Werror=redundant-move
PYTHON ?= python3
ZIG_VENV ?= .venv
SYSTEM_ZIG := $(shell command -v zig 2>/dev/null)
ZIG ?= $(if $(SYSTEM_ZIG),$(SYSTEM_ZIG),$(abspath $(ZIG_VENV))/bin/python-zig)
VERSION := $(or $(VERSION),$(shell date -u +%Y%m%d%H%M%S))
export VERSION
OUTPUT := build/mergerfs-webui$(if $(TARGET),_$(TARGET),)
SRC  := $(wildcard src/*.cpp)
HEADERS := $(wildcard src/*.h src/*.hpp vendored/*.h vendored/*.hpp)
OBJDIR := build/.objs$(if $(TARGET),/$(TARGET),)
OBJS := $(SRC:src/%.cpp=$(OBJDIR)/%.cpp.o)
DEPS := $(OBJS:.o=.d)
TESTS := $(wildcard tests/*.cpp)
TESTS_OBJS := $(TESTS:tests/%.cpp=build/.test_objs/%.cpp.o)
TESTS_OBJS += build/.test_objs/mergerfs_update.cpp.o
TESTS_DEPS := $(TESTS_OBJS:.o=.d)
override CPPFLAGS += -MMD -MP

ifeq ($(NDEBUG),1)
OPT ?= -Os -flto -ffunction-sections -fdata-sections -static
BUILD_FLAGS := $(OPT) -fno-rtti -DNDEBUG
RELEASE_LDFLAGS := -Wl,--gc-sections -Wl,--strip-all
else
OPT ?= -O0 -ggdb -ftrapv
BUILD_FLAGS := $(OPT)
endif

ZIG_RELEASE_OPT := -Oz -flto -ffunction-sections -fdata-sections -static

.DELETE_ON_ERROR:

.PHONY: all clean distclean help release zig-venv test test-browser force-version
all: $(OUTPUT)

build:
	mkdir -p $@

build/index.html.gz: webui/index.html | build
	gzip -9 -n -c $< > $@

build/index_html_gz.h: build/index.html.gz
	xxd -i -n index_html_gz $< > $@

$(OBJDIR)/version.h: force-version | $(OBJDIR)
	@printf 'static constexpr char VERSION[] = "%s";\n' "$(VERSION)" | cmp -s - $@ || \
	  printf 'static constexpr char VERSION[] = "%s";\n' "$(VERSION)" > $@

force-version:

$(OUTPUT): Makefile $(OBJS) $(HEADERS)
	$(CXX) $(BUILD_FLAGS) -pthread $(OBJS) -o $@ $(LDFLAGS) $(RELEASE_LDFLAGS)

$(OBJDIR):
	mkdir -p $@

build/.test_objs:
	mkdir -p $@

$(OBJDIR)/main.cpp.o: build/index_html_gz.h $(OBJDIR)/version.h

$(OBJDIR)/%.cpp.o: src/%.cpp Makefile | $(OBJDIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(BUILD_FLAGS) -Ivendored -I$(OBJDIR) -Ibuild -pthread -c $< -o $@

build/.test_objs/%.cpp.o: tests/%.cpp Makefile | build/.test_objs
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(BUILD_FLAGS) -DMERGERFS_UPDATE_TEST -Isrc -Ivendored -pthread -c $< -o $@

build/.test_objs/mergerfs_update.cpp.o: src/mergerfs_update.cpp Makefile | build/.test_objs
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(BUILD_FLAGS) -DMERGERFS_UPDATE_TEST -Isrc -Ivendored -pthread -c $< -o $@

build/test-mergerfs-update: build/.test_objs/mergerfs_update_driver.cpp.o build/.test_objs/mergerfs_update.cpp.o $(OBJDIR)/update_io.cpp.o
	$(CXX) $(BUILD_FLAGS) -pthread $^ -o $@ $(LDFLAGS) $(RELEASE_LDFLAGS)

build/test-service-install: build/.test_objs/service_install_driver.cpp.o $(OBJDIR)/service_install.cpp.o $(OBJDIR)/update_io.cpp.o
	$(CXX) $(BUILD_FLAGS) -pthread $^ -o $@ $(LDFLAGS) $(RELEASE_LDFLAGS)

test: $(OUTPUT) build/test-mergerfs-update build/test-service-install
	$(PYTHON) tests/test_installer.py
	$(PYTHON) tests/test_config_references.py $(OUTPUT)
	$(PYTHON) tests/test_persistence_preview.py $(OUTPUT)
	$(PYTHON) tests/test_update.py $(OUTPUT)
	$(PYTHON) tests/test_mergerfs_update.py build/test-mergerfs-update $(OUTPUT)
	$(PYTHON) tests/test_service_install.py $(OUTPUT) build/test-service-install

test-browser: $(OUTPUT)
	$(PYTHON) tests/test_browser_auth.py $(OUTPUT)

clean:
	rm -rf build

distclean: clean
	rm -rf .venv

help:
	@echo "make                  Native build"
	@echo "make NDEBUG=1         Size-optimized, statically linked native build (-Os, LTO, no RTTI, section GC, stripped)"
	@echo "make zig-venv         Install pinned Zig if none is on PATH"
	@echo "make release          Static Linux builds: x86_64, arm32, aarch64, riscv64"
	@echo "tools/release-to-github  Build all four binaries; tag and upload a draft release"
	@echo "make test             Config, update, restart, and sandboxed service lifecycle tests"
	@echo "make test-browser     Served-UI login test (requires Playwright and Chromium; see README)"
	@echo "make clean            Remove build artifacts"
	@echo "make distclean       Remove build artifacts and the local Zig virtualenv"

zig-venv:
ifneq ($(SYSTEM_ZIG),)
	@echo "Using system Zig: $(SYSTEM_ZIG)"
else
	$(PYTHON) -m venv "$(ZIG_VENV)"
	"$(ZIG_VENV)/bin/python" -m pip install "ziglang"
endif

release:
	@"$(ZIG)" version >/dev/null 2>&1 || { echo "Zig not found; run 'make zig-venv' first." >&2; exit 1; }
	$(MAKE) NDEBUG=1 OPT="$(ZIG_RELEASE_OPT)" TARGET=x86_64-linux-musl CXX="$(ZIG) c++ -target x86_64-linux-musl"
	$(MAKE) NDEBUG=1 OPT="$(ZIG_RELEASE_OPT)" TARGET=arm-linux-musleabihf CXX="$(ZIG) c++ -target arm-linux-musleabihf"
	$(MAKE) NDEBUG=1 OPT="$(ZIG_RELEASE_OPT)" TARGET=aarch64-linux-musl CXX="$(ZIG) c++ -target aarch64-linux-musl"
	$(MAKE) NDEBUG=1 OPT="$(ZIG_RELEASE_OPT)" TARGET=riscv64-linux-musl CXX="$(ZIG) c++ -target riscv64-linux-musl"

-include $(DEPS) $(TESTS_DEPS)
