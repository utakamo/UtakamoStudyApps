include $(TOPDIR)/rules.mk

PKG_NAME:=ubus-sample
PKG_VERSION:=1.0
PKG_RELEASE:=1

SOURCE_DIR:=./files/src
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)$(PKG_VERSION)-$(PKG_RELEASE)
TARGET_LDFLAGS+=-luci -lubus -lubox

include $(INCLUDE_DIR)/package.mk

define Package/ubus-sample
    CATEGORY:=utakamo
    SECTION:=utakamo
    TITLE:=ubus sample
    DEPENDS:=+libuci +libubus +libubox
endef

define Package/ubus-sample/description
	ubus sample program
endef

#copy src file from ubus-sample_dir to build_dir 
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

define Package/ubus-sample/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/ubus-sample.config $(1)/etc/config/ubus-sample
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/ubus-sample.init $(1)/etc/init.d/ubus-sample
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ubus-sample $(1)/usr/bin/ubus-sample
endef

$(eval $(call BuildPackage,ubus-sample))
