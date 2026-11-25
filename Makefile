APP_NAME := DockPicker.app
BUILD_DIR ?= build
APP_DIR := $(BUILD_DIR)/$(APP_NAME)
BINARY := $(APP_DIR)/Contents/MacOS/DockPicker
CLANG ?= xcrun clang
CODESIGN ?= codesign
# DockPicker Code Signing: reuse this certificate to preserve the application identity.
CODESIGN_IDENTITY ?= 445DE6AF6FBFAF2758DDF96541D4E19ACE2ADBB2
SIGNING_DIR ?= $(HOME)/Library/Application Support/DockPicker/Signing
CODESIGN_KEYCHAIN ?= $(SIGNING_DIR)/DockPicker-signing.keychain-db
CODESIGN_PASSWORD_FILE ?= $(SIGNING_DIR)/keychain-password

FRAMEWORKS := -framework AppKit -framework Carbon -framework Security -framework ApplicationServices

.PHONY: all build sign clean

all: build

build: sign

$(BINARY): Sources/main.m Resources/Info.plist Makefile
	@mkdir -p "$(APP_DIR)/Contents/MacOS"
	@cp Resources/Info.plist "$(APP_DIR)/Contents/Info.plist"
	$(CLANG) -fobjc-arc -Wno-deprecated-declarations $(FRAMEWORKS) -o "$(BINARY)" Sources/main.m

sign: $(BINARY)
	@set -e; \
	if [ -n "$(CODESIGN_KEYCHAIN)" ]; then \
		test -r "$(CODESIGN_PASSWORD_FILE)" || { printf '%s\n' 'DockPicker signing keychain password file is missing.' >&2; exit 1; }; \
		IFS= read -r dockpicker_keychain_password < "$(CODESIGN_PASSWORD_FILE)"; \
		/usr/bin/security unlock-keychain -p "$$dockpicker_keychain_password" "$(CODESIGN_KEYCHAIN)"; \
	fi
	$(CODESIGN) --force --sign "$(CODESIGN_IDENTITY)" $(if $(CODESIGN_KEYCHAIN),--keychain "$(CODESIGN_KEYCHAIN)") --timestamp=none "$(APP_DIR)"
	$(CODESIGN) --verify --deep --strict "$(APP_DIR)"

clean:
	rm -rf "$(BUILD_DIR)"
