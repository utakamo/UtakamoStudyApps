execute_cmd = function(cmd)
    local handle = io.popen(cmd)
    local result = handle:read('*a')
    handle:close()
    
    return result
end

split = function(inputString, delimiter)
    local result = {}
    local pattern = string.format("([^%s]+)", delimiter)
    
    for match in inputString:gmatch(pattern) do
        table.insert(result, match)
    end
    
    return result
end

m = Map("network", "Network Setting (kamo custom)")

s = m:section(TypedSection, "interface")
s.addremove = true
function s:filter(value)
    return value ~= "loopback" and value
end 
s:depends("proto", "static")
s:depends("proto", "dhcp")

p = s:option(ListValue, "proto", "Protocol")
p:value("static", "static")
p:value("dhcp", "dhcp")
p.default = "static"

d = s:option(ListValue, "device", "Device")
active_ifs = execute_cmd("ip link show up | awk '/^[0-9]+: / {print substr($2, 1, length($2)-1)}'")
active_iflist = split(active_ifs, '\n')

for _, v in ipairs(active_iflist) do
    d:value(v, v)
end

s:option(Value, "ipaddr", "ip"):depends("proto", "static")

s:option(Value, "netmask", "Netmask"):depends("proto", "static")

return m
