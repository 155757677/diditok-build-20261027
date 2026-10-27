# Makefile — Theos Tweak 构建
ARCHS = arm64 arm64e
TARGET = iphone:clang:17.5:13.4

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Diditok
Diditok_FILES = MyTweak.m
Diditok_CFLAGS = -fobjc-arc -Wall -Wno-error=deprecated-declarations -Wno-error=unused-function
Diditok_FRAMEWORKS = Foundation UIKit Security QuartzCore
Diditok_LDFLAGS = -undefined dynamic_lookup
Diditok_INSTALL_PATH = /Library/MobileSubstrate/DynamicLibraries/

SUBSTRATE_BUNDLE_ID_ORIGINAL = com.xiaojukeji.didi

include $(THEOS)/makefiles/tweak.mk
