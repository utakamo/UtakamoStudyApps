include $(TOPDIR)/rules.mk

PKG_NAME:=ubus-sample03
PKG_VERSION:=1.0
PKG_RELEASE:=1

SOURCE_DIR:=./files/src
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)$(PKG_VERSION)-$(PKG_RELEASE)
TARGET_LDFLAGS+=-lubus -lubox

include $(INCLUDE_DIR)/package.mk

define Package/ubus-sample03
    CATEGORY:=utakamo
    SECTION:=utakamo
    TITLE:=libubus(c-library) Sample Program for sending event
    DEPENDS:=+libubus +libubox
endef

define Package/ubus-sample03/description
	ubus sample program
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp $(SOURCE_DIR)/* $(PKG_BUILD_DIR)
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/ubus-sample03/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ubus-sample03 $(1)/usr/bin/ubus-sample03
endef

$(eval $(call BuildPackage,ubus-sample03))
