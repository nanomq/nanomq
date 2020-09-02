
include config.mk
export EMQ_DEBUG=

PKG_NAME:=NanoMQ
PKG_VERSION:=0.1

#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=
PKG_MD5SUM:=
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/NanoMQ
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=blazing fast + ultra lighweight MQTT edge broker
 #URL:=
  DEPENDS:=+libnl-tiny +librt
endef

define Package/NanoMQ/description
package to communicate with a dashboard
endef

define Package/NanoMQ/config

endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/ $(PKG_BUILD_DIR)/src
endef

define Build/Configure
endef

define Package/nng/postinst
#!/bin/sh

endef

TARGET_CFLAGS:= \
	-I$(STAGING_DIR)/usr/include/libnl-tiny \
	-I$(STAGING_DIR)/usr/include/ \
	$(TARGET_CFLAGS)

TARGET_LDFLAGS:= \
	-lnl-tiny \
	$(TARGET_LDFLAGS)

MAKE_FLAGS += \
	OFLAGS="$(TARGET_CFLAGS) $(TARGET_LDFLAGS)" \
	CC="$(TARGET_CC)" \
	STRIP="/bin/true"

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/src $(MAKE_FLAGS)
endef

define Package/NanoMQ/install

endef

$(eval $(call BuildPackage,dashboard))
