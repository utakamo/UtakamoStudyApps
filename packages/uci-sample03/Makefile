include $(TOPDIR)/rules.mk

PKG_NAME:=uci-sample03
PKG_VERSION:=1.0
PKG_RELEASE:=1

SOURCE_DIR:=/home/kamo/UtakamoApps/libuci-c/uci-sample03
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)$(PKG_VERSION)-$(PKG_RELEASE)
#Default PKG_BUILD_DIR
#PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

TARGET_LDFLAGS = -luci

include $(INCLUDE_DIR)/package.mk

define Package/uci-sample03
    CATEGORY:=utakamo
    SECTION:=utakamo
    TITLE:=libuci(c-libraly) sample program No.3
    DEPENDS:=+libuci
endef

define Package/uci-sample03/description
	program used uci_lookup_ptr func (2)
endef

#copy src file uci-sample03 to build_dir 
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

define Package/uci-sample03/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/uci-sample03 $(1)/usr/bin/uci-sample03
endef

$(eval $(call BuildPackage,uci-sample03))
