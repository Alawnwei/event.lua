local event = require "event"

for i = 1,1024 do

	event.dns("www.baidu.com",function (result,error)

		if result then
			table.print(result)
		else
			print(error)
		end
	end)

end
local helper = require "helper"

local count = 0
event.fork(function ()
	while true do
		event.sleep(1)
		event.dns("www.baidu.com",function (result,error)
			helper.free()
			print(collectgarbage("count"),helper.allocated()/1024)
			if result then
				table.print(result)
			else
				print(error)
			end

			count = count + 1
			print(count)
			if count >= 10 then
				event.breakout()
			end
		end)
	end
end)