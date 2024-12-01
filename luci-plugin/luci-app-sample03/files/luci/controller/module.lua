-- module.lua
module("luci.controller.luci-app-sample03.module", package.seeall)

function index()
    entry({"admin", "status", "custom-page"}, firstchild(), "luci-app-sample03", 30).dependent=false
    entry({"admin", "status", "custom-page", "network"}, cbi("luci-app-sample03/ioctl"), "IOCTL INFO", 30).dependent=false
    entry({"admin", "status", "custom-page", "network"}, cbi("luci-app-sample03/netlink"), "NETLINK INFO", 30).dependent=false
end