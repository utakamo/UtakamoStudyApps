include $(TOPDIR)/rules.mk

PKG_NAME:=duckdump
PKG_VERSION:=1.0
PKG_RELEASE:=1

SOURCE_DIR:=/home/kamo/UtakamoApps/duckdump
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)$(PKG_VERSION)-$(PKG_RELEASE)
#Default PKG_BUILD_DIR
#PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/duckdump
    SECTION:=utakamo
    CATEGORY:=utakamo
    DEPENDS:=+libpcap
    TARGET_LDFLAGS+=-lpcap
    TITLE:=utakamo packet capture
endef

define Package/duckdump/description
	ipv4 packet capture
endef

#copy src file from duckdump_dir to build_dir 
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

define Package/duckdump/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/duckdump.init $(1)/etc/init.d/duckdump	
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/duckdump.config $(1)/etc/config/duckdump
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/duckdump $(1)/usr/bin/duckdump
endef

$(eval $(call BuildPackage,duckdump))
