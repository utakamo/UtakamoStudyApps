include $(TOPDIR)/rules.mk

PKG_NAME:=procd-style
PKG_VERSION:=1.0
PKG_RELEASE:=1

SOURCE_DIR:=./files/src
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)$(PKG_VERSION)-$(PKG_RELEASE)
TARGET_LDFLAGS+=-luci -lubus -lubox

include $(INCLUDE_DIR)/package.mk

define Package/procd-style
    CATEGORY:=utakamo
    SECTION:=init script sample
    TITLE:=procd style init script sample 
    DEPENDS:=+libuci +libubus +libubox
endef

define Package/procd-style/description
	procd style init script sample program
endef

#copy src file from procd-style_dir to build_dir 
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

define Package/procd-style/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/procd-style.config $(1)/etc/config/procd-style
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/procd-style.init $(1)/etc/init.d/procd-style
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/procd-style $(1)/usr/bin/procd-style
endef

$(eval $(call BuildPackage,procd-style))
