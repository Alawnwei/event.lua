local event = require "event"


event.fork(function ()
	local timer = event.timer(1,function ()
		print("fuck")
	end)
	event.clean()
	collectgarbage("collect")
end)