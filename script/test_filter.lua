


local FILE = io.open("config/filter.lua")
local content = FILE:read("*a")
FILE:close()

local info = load("return "..content)()

local filter = require "filter"

local inst = filter.create()

for _,w in pairs(info.ForBiddenCharInName) do
	inst:add(w)
end

table.print(inst:dump())