include $(TOPDIR)/rules.mk

PKG_NAME:=ubus-sample02
PKG_VERSION:=1.0
PKG_RELEASE:=1

SOURCE_DIR:=./files/src
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)$(PKG_VERSION)-$(PKG_RELEASE)
TARGET_LDFLAGS+=-luci -lubus -lubox

include $(INCLUDE_DIR)/package.mk

define Package/ubus-sample02
    CATEGORY:=utakamo
    SECTION:=utakamo
    TITLE:=libubus(c-library) event listener sample
    DEPENDS:=+libuci +libubus +libubox
endef

define Package/ubus-sample02/description
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

define Package/ubus-sample02/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/ubus-sample02.init $(1)/etc/init.d/ubus-sample02
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ubus-sample02 $(1)/usr/bin/ubus-sample02
endef

$(eval $(call BuildPackage,ubus-sample02))
