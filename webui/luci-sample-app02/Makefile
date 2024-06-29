include $(TOPDIR)/rules.mk

PKG_NAME:=luci-sample-app02
PKG_VERSION:=1.0
PKG_RELEASE:=1

PLUGIN_SOURCE_DIR:=./src
LUA_SOURCE_DIR:=./webui

PLUGIN_DIR = /usr/libexec/rpcd
USR_BIN_DIR = /usr/bin
LUA_LIBRARYDIR = /usr/lib/lua
LUCI_LIBRARYDIR = $(LUA_LIBRARYDIR)/luci
LUCI_MODULEDIR = $(LUCI_LIBRARYDIR)/controller
LUCI_VIEWDIR = $(LUCI_LIBRARYDIR)/view


include $(INCLUDE_DIR)/package.mk

define Package/luci-sample-app02
    CATEGORY:=utakamo
    SECTION:=utakamo
    TITLE:=luci sample application
endef

define Build/Compile
endef

define Package/luci-sample-app02/install
	$(INSTALL_DIR) $(1)$(PLUGIN_DIR)
	$(INSTALL_DATA) $(PLUGIN_SOURCE_DIR)/usr/libexec/rpcd/ash-sample $(1)$(PLUGIN_DIR)
	$(INSTALL_DATA) $(PLUGIN_SOURCE_DIR)/usr/libexec/rpcd/lua-sample $(1)$(PLUGIN_DIR)
	$(INSTALL_DIR) $(1)$(USR_BIN_DIR)
	$(INSTALL_DATA) $(PLUGIN_SOURCE_DIR)/usr/bin/for-ash-sample.lua $(1)$(USR_BIN_DIR)
	$(INSTALL_DIR) $(1)$(LUCI_MODULEDIR)/luci-sample-app02
	$(INSTALL_DATA) $(LUA_SOURCE_DIR)/controller/module.lua $(1)$(LUCI_MODULEDIR)/luci-sample-app02
	$(INSTALL_DIR) $(1)$(LUCI_VIEWDIR)/luci-sample-app02
	$(INSTALL_DATA) $(LUA_SOURCE_DIR)/view/sample_ash_plugin.htm $(1)$(LUCI_VIEWDIR)/luci-sample-app02
	$(INSTALL_DATA) $(LUA_SOURCE_DIR)/view/sample_lua_plugin.htm $(1)$(LUCI_VIEWDIR)/luci-sample-app02
endef

$(eval $(call BuildPackage,luci-sample-app02))
