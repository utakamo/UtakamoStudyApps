include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-sample03
PKG_VERSION:=1.0
PKG_RELEASE:=1

SOURCE_DIR:=./files/src/bin
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)$(PKG_VERSION)-$(PKG_RELEASE)
TARGET_LDFLAGS+=-luci -lubus -lubox

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-sample03
    CATEGORY:=utakamo
    SECTION:=utakamo
    TITLE:=luci sample application
    DEPENDS:=+libuci +libubus +libubox
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

define Package/luci-app-sample03/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/luci-app-sample03 $(1)/usr/bin/luci-app-sample03
endef

$(eval $(call BuildPackage,luci-app-sample03))
