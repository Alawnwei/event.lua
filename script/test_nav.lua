local cjson = require "cjson"
local nav_core = require "nav.core"
local finder_core = require "pathfinder.core"
local util = require "util"

local file = "1001.nav"
local ctx = nav_core.create(string.format("./config/nav/%s",file))
ctx:load_tile(string.format("./config/nav/%s.tile",file))

local count = 100000
util.time_diff("find",function ()
	for i = 1,count do
		ctx:find(20400,33950,27600,10400)
	end
end)

util.time_diff("random",function ()
	for i = 1,count do
		ctx:random_point()
	end
end)

util.time_diff("height",function ()
	for i = 1,count do
		ctx:nav_height(16650,24550)
	end
end)


-- local finder = finder_core.create(101,"./config/nav.tile")
-- util.time_diff("finder",function ()
-- 	for i = 1,100000 do
-- 		finder:find(22,109,124,18)
-- 	end
-- end)
