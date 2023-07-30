include $(TOPDIR)/rules.mk

PKG_NAME:=ubus-sample01
PKG_VERSION:=1.0
PKG_RELEASE:=1

SOURCE_DIR:=./files/src
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)$(PKG_VERSION)-$(PKG_RELEASE)
TARGET_LDFLAGS+=-luci -lubus -lubox

include $(INCLUDE_DIR)/package.mk

define Package/ubus-sample01
    CATEGORY:=utakamo
    SECTION:=utakamo
    TITLE:=ubus sample
    DEPENDS:=+libuci +libubus +libubox
endef

define Package/ubus-sample01/description
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

define Package/ubus-sample01/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/ubus-sample01.config $(1)/etc/config/ubus-sample01
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/ubus-sample01.init $(1)/etc/init.d/ubus-sample01
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ubus-sample01 $(1)/usr/bin/ubus-sample01
endef

$(eval $(call BuildPackage,ubus-sample01))
