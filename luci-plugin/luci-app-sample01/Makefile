include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-sample01
PKG_VERSION:=1.0
PKG_RELEASE:=1

SOURCE_DIR:=./files/luasrc

LUA_LIBRARYDIR = /usr/lib/lua
LUCI_LIBRARYDIR = $(LUA_LIBRARYDIR)/luci
LUCI_MODULEDIR = $(LUCI_LIBRARYDIR)/controller
LUCI_MODELDIR = $(LUCI_LIBRARYDIR)/model/cbi
LUCI_VIEWDIR = $(LUCI_LIBRARYDIR)/view

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-sample01
    CATEGORY:=utakamo
    SECTION:=utakamo
    TITLE:=luci sample application
    DEPENDS:=+luci-compat
    PKGARCH:=all
endef

define Build/Compile
endef

define Package/luci-app-sample01/install
	$(INSTALL_DIR) $(1)$(LUCI_MODULEDIR)/luci-app-sample01
	$(INSTALL_DATA) $(SOURCE_DIR)/controller/module.lua $(1)$(LUCI_MODULEDIR)/luci-app-sample01
	$(INSTALL_DIR) $(1)$(LUCI_MODELDIR)/luci-app-sample01
	$(INSTALL_DATA) $(SOURCE_DIR)/model/cbi/network.lua $(1)$(LUCI_MODELDIR)/luci-app-sample01
	$(INSTALL_DATA) $(SOURCE_DIR)/model/cbi/wireless.lua $(1)$(LUCI_MODELDIR)/luci-app-sample01
	$(INSTALL_DIR) $(1)$(LUCI_VIEWDIR)/luci-app-sample01
	$(INSTALL_DATA) $(SOURCE_DIR)/view/cbi/desc.htm $(1)$(LUCI_VIEWDIR)/luci-app-sample01
endef

$(eval $(call BuildPackage,luci-app-sample01))
