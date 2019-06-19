require "lfs"
local util = require "util"
local event = require "event"

local _M = {}

local _script_ctx = {}

local function loadfile(file,fullfile,env)
	local attr = lfs.attributes(fullfile)
	if not attr then
		error(string.format("no such file:%s,path:%s",file,fullfile))
	end

	local fd = io.open(fullfile,"r")
	local buffer = fd:read("*a")
	fd:close()

	local func,localvar = util.load_script(buffer,string.format("@user.%s",file),env)
	func()
	return attr.change
end

local function env_pairs(self,key)
	local key,value = next(self,key)
	if key == "__name" or key == "__timer" then
		return next(self,key)
	end
	return key,value
end

function _M.import(file)
	local ctx = _script_ctx[file]
	if ctx then
		return ctx.env
	end

	local fullfile,change = string.format("./script/%s.lua",string.gsub(file,"%.","/"))

	local ctx = {}
	
	
	ctx.env = setmetatable({},{__index = _G,__pairs = function (self) return env_pairs,self end})
	ctx.env.__name = fullfile
	ctx.env.__timer = {}
	
	ctx.change = loadfile(file,ctx.env.__name,ctx.env)

	if ctx.env["__init__"] then
		ctx.env["__init__"](ctx.env)
	end

	_script_ctx[file] = ctx
	
	return ctx.env
end

function _M.reload(file)
	local ctx = _script_ctx[file]
	if not ctx then
		return
	end

	ctx.change = loadfile(file,ctx.__name,ctx.env)

	if ctx.env["__init__"] then
		ctx.env["__init__"](ctx.env)
	end

	if ctx.env["__reload__"] then
		ctx.env["__reload__"](ctx.env)
	end
end

function _M.auto_reload()
	local list = {}
	for file,ctx in pairs(_script_ctx) do
		local attr = lfs.attributes(ctx.fullfile)
		if attr.change ~= ctx.change then
			_M.reload(file)
			table.insert(list,file)
		end
	end
	return list
end

function _M.get_script_ctx()
	return _script_ctx
end

function _M.get_module(file)
	local ctx = _script_ctx[file]
	if ctx then
		return ctx.env
	end
end

function _M.dispatch(file,method,...)
	local ctx = _script_ctx[file]
	if not ctx then
		error(string.format("no such file:%s",file))
	end

	local func = ctx.env[method]
	if not func then
		error(string.format("no such method:%s",method))
	end

	return func(...)
end

return _M
