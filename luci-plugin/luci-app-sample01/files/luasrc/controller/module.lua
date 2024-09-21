module("luci.controller.luci-app-sample01.module", package.seeall)

function index()
	entry({"utakamo", "luci-app-sample01", "desc"}, template("luci-app-sample01/desc"), "desc", 20).dependent=false
	entry({"admin", "network", "custom-page"}, firstchild(), "CUSTOM PAGE", 30).dependent=false
	entry({"admin", "network", "custom-page", "wireless"}, cbi("luci-app-sample01/wireless"), "Wi-Fi Setting (kamo custom)", 30).dependent=false
	entry({"admin", "network", "custom-page", "network"}, cbi("luci-app-sample01/network"), "Network Setting (kamo custom)", 30).dependent=false
end
