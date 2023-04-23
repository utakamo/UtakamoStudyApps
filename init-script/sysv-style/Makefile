include $(TOPDIR)/rules.mk

PKG_NAME:=sysv-style
PKG_VERSION:=1.0
PKG_RELEASE:=1

SOURCE_DIR:=./files/src
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)$(PKG_VERSION)-$(PKG_RELEASE)
TARGET_LDFLAGS+=-luci

include $(INCLUDE_DIR)/package.mk

define Package/sysv-style
    CATEGORY:=utakamo
    SECTION:=init script sample
    TITLE:=sysv style init script sample 
    DEPENDS:=+libuci
endef

define Package/sysv-style/description
	sysv style init script sample program
endef

#copy src file from sysv-style_dir to build_dir 
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

define Package/sysv-style/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/sysv-style.config $(1)/etc/config/sysv-style
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/sysv-style.init $(1)/etc/init.d/sysv-style
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sysv-style $(1)/usr/bin/sysv-style
endef

$(eval $(call BuildPackage,sysv-style))
