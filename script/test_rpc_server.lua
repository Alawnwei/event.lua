local event = require "event"
local channel = require "channel"
local helper = require "helper"
import "handler.test_handler"

local util = require "util"
-- util.profiler_stack_start("lua.prof")
event.fork(function ()
	local channel,err = event.listen("tcp://127.0.0.1:1989",4,function (channel,addr)
		print(addr)

	end,channel,false)
	if not channel then
		event.breakout(err)
	end
end)

event.fork(function ()
	while true do
		event.sleep(5)
		local mem = collectgarbage("count")
		print(string.format("lua mem:%fkb,c mem:%fkb",mem,helper.allocated() / 1024))
	end
end)