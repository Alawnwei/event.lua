
local _M = {}


local _binderCtx = {}
local _valueCtx = {}


function _M.registerBinder(name,...)
	local keys = {...}
	assert(#keys ~= 0)

	local firstKey = keys[1]

	assert(_binderCtx[name] == nil,string.format("name:%s already register",name))
	_binderCtx[name] = {}
	
	_M[string.format("fetch_%s",name)] = function ()
		local ctxInfo = _binderCtx[name]
		if ctxInfo and ctxInfo[firstKey] then
			local result = {}
			for _,info in pairs(ctxInfo[firstKey]) do
				table.insert(result,info.value)
			end
			return result
		end	
	end

	for _,key in pairs(keys) do
		if not _binderCtx[name][key] then
			_binderCtx[name][key] = {}
		end

		_M[string.format("fetch_%s_with_%s",name,key)] = function (k)
			local ctxInfo = _binderCtx[name]
			local info = ctxInfo[key]
			if not info[k] then
				return
			end
			return info[k].value
		end

		_M[string.format("bind_%s_with_%s",name,key)] = function (k,value)
			local ctxInfo = _binderCtx[name]
			local info = ctxInfo[key]
			if not info then
				ctxInfo[key] = {}
				info = ctxInfo[key]
			end
			info[k] = {time = os.time(),value = value}
		end

		_M[string.format("unbind_%s_with_%s",name,key)] = function (k)
			local ctxInfo = _binderCtx[name]
			local info = ctxInfo[key]
			info[k] = nil
		end
	end
end

function _M.registerValue(name)
	_M[string.format("set_%s",name)] = function (value)
		_valueCtx[name] = {time = os.time(),value = value}
	end

	_M[string.format("get_%s",name)] = function ()
		local ctx = _valueCtx[name]
		if ctx then
			return ctx.value
		end
		return
	end

	_M[string.format("delete_%s",name)] = function ()
		_valueCtx[name] = nil
	end
end

function _M.countModel()
	local value_report = {}
	for name,ctx in pairs(_valueCtx) do
		local now = math.modf(ctx.now / 100)
		table.insert(value_report,string.format("born:%s,value:%s",os.date("%Y-%m-%d %H:%M:%S",now),ctx.value))
	end

	local binder_report = {}
	for name,binder in pairs(_binderCtx) do
		local report = {}
		for key,ctx in pairs(binder) do
			local key_report = {}
			for k,v in pairs(ctx) do
				local now = math.modf(v.now / 100)
				table.insert(key_report,string.format("born:%s,k:%s,v:%s",os.date("%Y-%m-%d %H:%M:%S",now),k,v.value))
			end
			report[key] = key_report
		end
		binder_report[name] = report
	end

	return table.tostring(value_report),table.tostring(binder_report)
end


return _M