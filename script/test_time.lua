local util = require "util"

local count = 1024*1024

util.time_diff("time0",function ()
	for  i = 1,count do
		util.day_time(os.time(),12,0,0)
		-- print(util.day_time(os.time(),12,0,0))
	end
end)

util.time_diff("time1",function ()
	for  i = 1,count do
		util.day_time0(os.time(),12,0,0)
		-- print(util.day_time0(os.time(),12,0,0))
	end
end)


util.time_diff("day_start",function ()
	for  i = 1,count do
		util.day_start(os.time())
		-- print(util.day_start(os.time()))
	end
end)

util.time_diff("day_start0",function ()
	for  i = 1,count do
		util.day_start0(os.time())
		-- print(util.day_start0(os.time()))
	end
end)

util.time_diff("day_over",function ()
	for  i = 1,count do
		util.day_over(os.time())
		-- print(util.day_over(os.time()))
	end
end)

util.time_diff("day_over0",function ()
	for  i = 1,count do
		util.day_over0(os.time())
		-- print(util.day_over0(os.time()))
	end
end)

util.time_diff("week_start",function ()
	for  i = 1,count do
		util.week_start(os.time())
		-- print(util.week_start(os.time()))
	end
end)

util.time_diff("week_start0",function ()
	for  i = 1,count do
		util.week_start0(os.time())
		-- print(util.week_start0(os.time()))
	end
end)

util.time_diff("week_over",function ()
	for  i = 1,count do
		util.week_over(os.time())
		-- print(util.week_over(os.time()))
	end
end)

util.time_diff("week_over0",function ()
	for  i = 1,count do
		util.week_over0(os.time())
		-- print(util.week_over0(os.time()))
	end
end)
