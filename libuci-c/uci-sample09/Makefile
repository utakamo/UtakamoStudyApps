include $(TOPDIR)/rules.mk

PKG_NAME:=uci-sample09
PKG_VERSION:=1.0
PKG_RELEASE:=1

SOURCE_DIR:=./src
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)$(PKG_VERSION)-$(PKG_RELEASE)
#Default PKG_BUILD_DIR
#PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

TARGET_LDFLAGS = -luci

include $(INCLUDE_DIR)/package.mk

define Package/uci-sample09
    CATEGORY:=utakamo
    SECTION:=utakamo
    TITLE:=libuci(c-libraly) sample program No.9 [uci_reorder_section]
    DEPENDS:=+libuci
endef

define Package/uci-sample09/description
	program used uci_reorder_section func
endef

#copy src file uci-sample09 to build_dir 
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

define Package/uci-sample09/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/uci-sample09 $(1)/usr/bin/uci-sample09
endef

$(eval $(call BuildPackage,uci-sample09))
