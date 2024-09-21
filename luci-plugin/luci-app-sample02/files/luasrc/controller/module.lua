-- module.lua
module("luci.controller.luci-app-sample02.module", package.seeall)

function index()
    entry({"admin", "status", "sample_ash_plugin"}, template("luci-app-sample02/sample_ash_plugin"), _("Sample Ash Plugin"), 90)
    entry({"admin", "status", "sample_lua_plugin"}, template("luci-app-sample02/sample_lua_plugin"), _("Sample Lua Plugin"), 90)
    entry({"admin", "status", "sample_ash_plugin", "active_if_list"}, call("action_sample_ash_plugin_active_if_list"), nil).leaf = true
    entry({"admin", "status", "sample_ash_plugin", "interface_ip4"}, call("action_sample_ash_plugin_interface_ip4"), nil).leaf = true
    entry({"admin", "status", "sample_ash_plugin", "interface_mac"}, call("action_sample_ash_plugin_interface_mac"), nil).leaf = true
    entry({"admin", "status", "sample_lua_plugin", "config_detail"}, call("action_sample_lua_plugin"), nil).leaf = true
end

-- [References] https://openwrt.org/docs/techref/ubus#lua_module_for_ubus
function ubus_call(path, method, param)
    local ubus = require("ubus")
    local conn = ubus.connect()

    if not conn then
        return { error = "Unable to connect to ubus" }
    end

    local result, err = conn:call(path, method, param)
    conn:close()

    if not result then
        return { error = err or "ubus call failed" }
    end

    return result
end

function action_sample_ash_plugin_active_if_list()
    local luci_http = require "luci.http"
    
    -- ubus call
    local result = ubus_call("ash-sample", "active_if_list", {})

    luci_http.prepare_content("application/json")
    luci_http.write_json(result)
end

function action_sample_ash_plugin_interface_ip4()
    local luci_http = require "luci.http"

    -- Get parameters from the HTTP request
    local params = luci_http.formvalue("params")

    if not params then
        luci_http.prepare_content("application/json")
        luci_http.write_json({ error = "Missing params" })
        return
    end

    -- Create a parameter table for ubus call
    local json_param = { ifname = params }
    
    -- ubus call
    local result = ubus_call("ash-sample", "interface_ip4", json_param)

    luci_http.prepare_content("application/json")
    luci_http.write_json(result)
end

function action_sample_ash_plugin_interface_mac()
    local luci_http = require "luci.http"

    -- Get parameters from the HTTP request
    local params = luci_http.formvalue("params")

    if not params then
        luci_http.prepare_content("application/json")
        luci_http.write_json({ error = "Missing params" })
        return
    end

    -- Create a parameter table for ubus call
    local json_param = { ifname = params }
    
    -- ubus call
    local result = ubus_call("ash-sample", "interface_mac", json_param)

    luci_http.prepare_content("application/json")
    luci_http.write_json(result)
end

function action_sample_lua_plugin()
    local luci_http = require "luci.http"
    
    -- Get parameters from the HTTP request
    local params = luci_http.formvalue("params")

    if not params then
        luci_http.prepare_content("application/json")
        luci_http.write_json({ error = "Missing params" })
        return
    end

    -- Create a parameter table for ubus call
    local json_param = { config = params }
    
    -- ubus call
    local result = ubus_call("lua-sample", "config_detail", json_param)

    luci_http.prepare_content("application/json")
    luci_http.write_json(result)
end