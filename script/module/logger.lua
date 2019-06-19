local event = require "event"
local util = require "util"
local model = require "model"
local serverMgr = import "module.server_manager"

local kLOG_LV_ERROR 	= 0
local kLOG_LV_WARN 		= 1
local kLOG_LV_INFO 		= 2
local kLOG_LV_DEBUG 	= 3


local eLOG_TAG = {
	[kLOG_LV_ERROR] 	= "E",
	[kLOG_LV_WARN] 		= "W",
	[kLOG_LV_INFO] 		= "I",
	[kLOG_LV_DEBUG] 	= "D",
}

local tconcat = table.concat
local strformat = string.format
local tostring = tostring
local osTime = os.time

local loggerCtx = {}

local _M = {}

function _M:create(logName,depth)
	logName = logName or "unknown"
	depth = depth or 4

	local logger = loggerCtx[logName]
	if logger then
		return logger
	end

	local ctx = setmetatable({},{__index = self})
	ctx.logLevel = env.logLevel or kLOG_LV_DEBUG
	ctx.logName = logName
	ctx.depth = depth

	loggerCtx[logName] = ctx

	return ctx
end

local function getDebugInfo(logger)
	local info = debug.getinfo(logger.depth,"lS")
	return info.source,info.currentline
end

local function appendLog(logger,fm,logLevel,...)
	local mb = {
		logLevel = logLevel,
		logTag = eLOG_TAG[logLevel],
		logName = logger.logName,
		time = osTime(),
		server = env.name,
		fm = fm,
		log = {...},
	}
	
	if logLevel == kLOG_LV_ERROR then
		local source,line = getDebugInfo(logger)
		mb.source = source
		mb.line = line
	end

	serverMgr:sendLog("handler.logger_handler","log",mb)
end

function _M:DEBUG(...)
	if self.logLevel < kLOG_LV_DEBUG then
		return
	end
	return appendLog(self,nil,kLOG_LV_DEBUG,...)
end

function _M:DEBUG_FM(fm,...)
	if self.logLevel < kLOG_LV_DEBUG then
		return
	end
	return appendLog(self,fm,kLOG_LV_DEBUG,...)
end

function _M:INFO(...)
	if self.logLevel < kLOG_LV_INFO then
		return
	end
	return appendLog(self,nil,kLOG_LV_INFO,...)
end

function _M:INFO_FM(fm,...)
	if self.logLevel < kLOG_LV_INFO then
		return
	end
	return appendLog(self,fm,kLOG_LV_INFO,...)
end

function _M:WARN(...)
	if self.logLevel < kLOG_LV_WARN then
		return
	end
	return appendLog(self,nil,kLOG_LV_WARN,...)
end

function _M:WARN_FM(fm,...)
	if self.logLevel < kLOG_LV_WARN then
		return
	end
	return appendLog(self,fm,kLOG_LV_WARN,...)
end

function _M:ERROR(...)
	if self.logLevel < kLOG_LV_ERROR then
		return
	end
	return appendLog(self,nil,kLOG_LV_ERROR,...)
end

function _M:ERROR_FM(fm,...)
	if self.logLevel < kLOG_LV_ERROR then
		return
	end
	return appendLog(self,fm,kLOG_LV_ERROR,...)
end


return _M