include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-sample03
PKG_VERSION:=1.0
PKG_RELEASE:=1

SOURCE_DIR:=./files/src/bin
LUA_SCRIPT_DIR:=./files/luci

LUA_LIBRARYDIR = /usr/lib/lua
LUCI_LIBRARYDIR = $(LUA_LIBRARYDIR)/luci
LUCI_MODULEDIR = $(LUCI_LIBRARYDIR)/controller
LUCI_MODELDIR = $(LUCI_LIBRARYDIR)/model/cbi
LUCI_VIEWDIR = $(LUCI_LIBRARYDIR)/view

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
	$(INSTALL_DIR) $(1)$(LUCI_MODULEDIR)/luci-app-sample3
	$(INSTALL_DATA) $(LUA_SCRIPT_DIR)/controller/module.lua $(1)$(LUCI_MODULEDIR)/luci-app-sample03
	$(INSTALL_DIR) $(1)$(LUCI_MODELDIR)/luci-app-sample03
	$(INSTALL_DATA) $(LUA_SCRIPT_DIR)/model/ioctl.lua $(1)$(LUCI_MODELDIR)/luci-app-sample03
	$(INSTALL_DATA) $(LUA_SCRIPT_DIR)/model/netlink.lua $(1)$(LUCI_MODELDIR)/luci-app-sample03
endef

$(eval $(call BuildPackage,luci-app-sample03))
