module("luci.controller.luci-sample-app01.module", package.seeall)

function index()
	entry({"utakamo", "luci-sample-app01", "desc"}, template("luci-sample-app01/desc"), "desc", 20).dependent=false
	entry({"admin", "network", "custom-page"}, firstchild(), "CUSTOM PAGE", 30).dependent=false
	entry({"admin", "network", "custom-page", "wireless"}, cbi("luci-sample-app01/wireless"), "Wi-Fi Setting (kamo custom)", 30).dependent=false
	entry({"admin", "network", "custom-page", "network"}, cbi("luci-sample-app01/network"), "Network Setting (kamo custom)", 30).dependent=false
end
