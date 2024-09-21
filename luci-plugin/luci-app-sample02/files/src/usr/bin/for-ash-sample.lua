#!/usr/bin/lua
local uci = require("luci.model.uci").cursor()
local json = require "luci.jsonc"

local execute = function(cmd)
    local handle = io.popen(cmd) --環境によっては実行できないこともあるそうです
    local result = handle:read('*a')
    handle:close()
    
    return result
end

if #arg ~= 2 then
    print('{ "error": { "reason": "No argument" }}')
    return
end

local method_param = json.parse(arg[2])

local data = {}

if arg[1] == 'interface_ip4' then
    cmd = "ifconfig " .. method_param.ifname .. " | sed -n 's/.*inet addr:\\([0-9\\.]*\\).*/\\1/p' | tr -d '\n'"
    data.addr = execute(cmd)
    
    if #data.addr == 0 then
        data.addr = "none"
    end

elseif arg[1] == 'interface_mac' then
    cmd =  "ifconfig " .. method_param.ifname .. " | awk '/HWaddr/ {print $5}' | tr -d '\n'"
    data.mac = execute(cmd)

    if #data.mac == 0 then
        data.mac = "00:00:00:00:00:00"
    end
end

if not next(data) then
    print('{ "error": { "reason": "no result" }}')
    return
end

local json_output = json.stringify(data, false)
print(json_output)