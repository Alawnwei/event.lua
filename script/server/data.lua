local event = require "event"
local util = require "util"
local helper = require "helper"
local dataServer = import "module.data.data_server"

event.fork(function ()
	event.listen("ipc://data.ipc",4,function (channel)

	end)

	dataServer:start(4)

	-- util.time_diff("load",function ()
	-- 	for i = 1,1024 * 100 do
	-- 		dataServer:loadUser({userUid = i})
	-- 	end
	-- end)

	local now = util.time()
	for i = 1,1024*100 do
		event.fork(function ()
			dataServer:loadUser({userUid = i})
			if i % 1000 == 0 then
				print(i)
			end
			if i == 1024*100 then
				print(util.time() - now)
				-- event.breakout()
			end
		end)
	end

	-- event.fork(function ()
	-- 	while true do
	-- 		event.sleep(1)
	-- 		collectgarbage("collect")
	-- 		event.clean()
	-- 		print(collectgarbage("count"),helper.allocated()/1024)
	-- 	end
	-- end)
	-- dataServer:loadUser({userUid = 1})
	-- dataServer:updateUser({userUid = 1,tbName = "user",updater = {level = 10,name = "mrq"}})
end)