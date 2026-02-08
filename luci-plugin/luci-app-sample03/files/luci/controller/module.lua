module("luci.controller.luci-app-sample03.module", package.seeall)

local http = require "luci.http"
local jsonc = require "luci.jsonc"
local ubus = require "ubus"

local function run_ubus(path, method, args)
	local conn = ubus.connect()
	if not conn then
		return false, "Failed to connect to ubus."
	end

	local ok, res = pcall(function()
		return conn:call(path, method, args or {})
	end)

	conn:close()

	if not ok then
		return false, res
	end

	return true, res
end

function index()
	entry({"admin", "status", "custom-page"}, firstchild(),
		_("luci-app-sample03"), 30).dependent = false

	entry({"admin", "status", "custom-page", "ioctl"},
		template("luci-app-sample03/ioctl"),
		_("IOCTL Tool"), 10).dependent = false

	entry({"admin", "status", "custom-page", "netlink"},
		template("luci-app-sample03/netlink"),
		_("Netlink Tool"), 20).dependent = false

	entry({"admin", "status", "custom-page", "api", "ioctl", "call"},
		post("action_ioctl_call")).leaf = true

	entry({"admin", "status", "custom-page", "api", "netlink", "call"},
		post("action_netlink_call")).leaf = true
end

local function parse_body()
	local body = http.content()
	if not body or #body == 0 then
		return {}
	end
	return jsonc.parse(body) or {}
end

local function respond(ok, payload, status)
	http.status(status or (ok and 200 or 500), ok and "OK" or "FAIL")
	http.prepare_content("application/json")
	http.write_json(payload)
end

function action_ioctl_call()
	local payload = parse_body()
	local method = payload.method
	local args = payload.args or {}

	if type(method) ~= "string" or method == "" then
		respond(false, { ok = false, message = "Method is not specified." }, 400)
		return
	end

	local ok, res = run_ubus("ioctl-tool", method, args)
	if not ok then
		respond(false, { ok = false, message = res or "ubus call failed." }, 500)
		return
	end

	respond(true, { ok = true, result = res or {} })
end

function action_netlink_call()
	local payload = parse_body()
	local method = payload.method
	local args = payload.args or {}

	if type(method) ~= "string" or method == "" then
		respond(false, { ok = false, message = "Method is not specified." }, 400)
		return
	end

	local ok, res = run_ubus("netlink-tool", method, args)
	if not ok then
		respond(false, { ok = false, message = res or "ubus call failed." }, 500)
		return
	end

	respond(true, { ok = true, result = res or {} })
end
