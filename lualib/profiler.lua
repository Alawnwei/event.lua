local util = require "util"


local _M = {}

local SORT = {
	SELF = 1,
	TOTAL = 2,
	MEM = 3
}
function _M.start(sort,hook_c)
	local ctx = {stop = util.profiler_start(hook_c),sort = sort}
	return ctx
end

function _M.stop(ctx)
	local time,record = ctx.stop()
	print(time)
	local list = {}
	local name_max = -1
	for name,info in pairs(record) do
		info.name = name
		local name_len = #name
		if name_max == -1 or name_max < name_len then
			name_max = name_len
		end
		table.insert(list,info)
	end

	table.sort(list,function (l,r)
		if ctx.sort == SORT.SELF then
			return l.invoke_cost > r.invoke_cost
		elseif ctx.sort == SORT.TOTAL then
			return l.invoke_diff > r.invoke_diff
		else
			return l.alloc_total > r.alloc_total
		end
	end)

	local pattern = string.format("%%-0%ds",name_max)
	local pattern_header = pattern.." %-015s %-021s %-021s %-015s %-015s"
	local pattern_line = pattern.." %-015d (%-03d%%)%-015f (%-03d%%)%-015f %-015d %-015d"
	
	print(string.format(pattern_header,"name","count","cost(self)","cost(total)","alloc total","alloc count"))
	for _,info in ipairs(list) do
		local self_ration = math.modf((info.invoke_cost * 100) / time)
		if self_ration > 100 then
			self_ration = 100
		end
		local total_ration = math.modf((info.invoke_diff * 100) / time)
		if total_ration > 100 then
			total_ration = 100
		end
		print(string.format(pattern_line,info.name,info.invoke_count,self_ration,info.invoke_cost,total_ration,info.invoke_diff,info.alloc_total,info.alloc_count))
	end
end

return _M