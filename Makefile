APP_NAME := DockPicker.app
BUILD_DIR ?= build
APP_DIR := $(BUILD_DIR)/$(APP_NAME)
BINARY := $(APP_DIR)/Contents/MacOS/DockPicker
CLANG ?= xcrun clang
CODESIGN ?= codesign

FRAMEWORKS := -framework AppKit -framework Carbon -framework Security -framework ApplicationServices

.PHONY: all build clean

all: build

build: $(BINARY)

$(BINARY): Sources/main.m Resources/Info.plist
	@mkdir -p "$(APP_DIR)/Contents/MacOS"
	@cp Resources/Info.plist "$(APP_DIR)/Contents/Info.plist"
	$(CLANG) -fobjc-arc -Wno-deprecated-declarations $(FRAMEWORKS) -o "$(BINARY)" Sources/main.m
	$(CODESIGN) --force --sign - "$(APP_DIR)"
	$(CODESIGN) --verify --deep --strict "$(APP_DIR)"

clean:
	rm -rf "$(BUILD_DIR)"
