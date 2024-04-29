
ubus = require("ubus")

-- [References] https://openwrt.org/docs/techref/ubus#lua_module_for_ubus
ubus_call = function(path, method, json_param)

    local conn = ubus.connect()

    if not conn then
        return
    end

    local result = conn:call(path, method, json_param)

    return result
end

m = Map("wireless", "Wi-Fi Setting (kamo custom)")
radio = m:section(TypedSection, "wifi-device")
radio.addremove = true
function radio:filter(value)
    return value
end 

wave = radio:option(ListValue, "disabled", "Wi-Fi Carrier Wave")
wave:value("1", "OFF")
wave:value("0", "ON")

country_code = radio:option(ListValue, "country", "COUNTRY")
wlan = ubus_call("iwinfo", "devices", {})

if #wlan.devices >= 1 then
    countrylist = ubus_call("iwinfo", "countrylist", {device = wlan.devices[1]})
    for _, item in ipairs(countrylist.results) do
        country_code:value(item.code, item.country)
    end
end

txpower = radio:option(ListValue, "txpower", "TXPOWER")

if #wlan.devices >= 1 then

    txpowerlist = ubus_call("iwinfo", "txpowerlist", {device = wlan.devices[1]})

    for _, result in ipairs(txpowerlist.results) do
	if (result.dbm >= 6) and (result.dbm <= 10) then
            txpower:value(result.mw, result.dbm .. "dBm")
        end
    end
end

default_radio = m:section(TypedSection, "wifi-iface")
default_radio.addremove = true
function default_radio:filter(value)
    return value
end

-- [References] https://openwrt.org/docs/guide-user/network/wifi/basic#common_options
encryption = default_radio:option(ListValue, "encryption", "ENCRYPTION")
encryption:value('none', 'no authentication')
encryption:value('psk+tkip+ccmp', 'WPA Personal (PSK)')
encryption:value('psk2', 'WPA2 Personal (PSK)')
encryption:value('sae', 'WPA3 Personal (SAE)')

default_radio:option(Value, "ssid", "SSID")
key = default_radio:option(Value, "key", "KEY")
key:depends("encryption", 'psk+tkip+ccmp')
key:depends("encryption", 'psk2')
key:depends("encryption", 'sae')
key.password = true

return m
