local event = require "event"
local channel = require "channel"

local count = 0
for i = 1,50 do
	event.fork(function ()
		local channel,err = event.connect("tcp://111.230.136.170:1989",4,false,channel)
		if not channel then
			event.breakout(err)
			return
		end

		while true do
			for i = 1,100 do
				count = count + 1
				channel:call("handler.test_handler","test_rpc",{fuck = 1})
				-- if count == 100000 then
				-- 	os.exit()
				-- end
			end
			event.sleep(0.2)
		end
	end)
end