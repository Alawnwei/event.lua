


local util = require "util"

local FILE = io.open("./config/name.lua","r")
local content = FILE:read("*a")
FILE:close()

local name_cfg = load(content)()

local name_list = {}
local name_map = {}

local what = {"FeMale","Male"}
for i = 1,60000 do
	local index = math.random(1,2)
	local cfg = name_cfg[what[index]]
	while true do
		local name = cfg[1][math.random(1,#cfg[1])]..cfg[2][math.random(1,#cfg[2])]..cfg[3][math.random(1,#cfg[3])]
		if not name_map[name] then
			name_map[name] = true
			table.insert(name_list,name)
			break
		end
	end
end

local content = table.concat(name_list,"\r\n")
local out
local count = 100
util.time_diff("compress",function ()
	for i = 1,count do
		out = util.zlib_compress(content)
	end
end)

print(content:len(),out:len())
util.time_diff("uncompress",function ()
	for i = 1,count do
		content = util.zlib_decompress(out,content:len())
	end
end)

util.time_diff("lz4_compress",function ()
	for i = 1,count do
		out = util.lz4_compress(content)
	end
end)

print(content:len(),out:len())
util.time_diff("lz4_uncompress",function ()
	for i = 1,count do
		content = util.lz4_decompress(out,content:len())
	end
end)

