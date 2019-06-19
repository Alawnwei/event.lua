local util = require "util"
local dump = require "dump.core"

-- print(util.size_of("111111"))
-- print(util.size_of("111111xvdfgdsssssssssssssssssssssssssssbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))


-- print(util.size_of(true))
-- print(util.size_of(1989))
-- print(util.size_of(1989.1006))
-- print(util.size_of(filter_inst0))
-- print(util.size_of(aoi))

local FILE = assert(io.open("./config/filter.lua","r"))
local content = FILE:read("*a")
FILE:close()

local count = collectgarbage("count")

local filter_list = dump.unpack(content)


print(util.size_of(filter_list))
print(util.size_of(content))

print("mem",collectgarbage("count") - count)

local eSCENE_DEFINE = {
	CITY = 1,
	
}

local kLOGIN_MAX = 1

local g_mount = 1

local _amount = 1


local cScene = {}
local  = {
	id = 1,
	_name = "fuck"
	__timer = ""
}A

local function _enter_city()


end

local function enter_scene()

end

function cScene:enter()

end
