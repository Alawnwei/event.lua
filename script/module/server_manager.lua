local event = require "event"
local model = require "model"
local channel = require "channel"
local mongo = require "mongo"
local util = require "util"
local persistence = require "persistence"

local object = import "module.object"

_serverCountor = _serverCountor or nil

_serverChannel = _serverChannel or {}

_loggerChannel = _loggerChannel or nil
_loginChannel = _loginChannel or nil
_worldChannel = _worldChannel or nil

_eventListener = _eventListener or object.cObject:new()

local function setChannel(name,channel)
	if name == "logger" then
		_loggerChannel = channel
	elseif name == "login" then
		_loginChannel = channel
	elseif name == "world" then
		_worldChannel = channel
	end
end

local cClientChannel = channel:inherit()
function cClientChannel:disconnect()
	_serverChannel[self.id] = nil
	setChannel(self.name,nil)
	_eventListener:fireEvent("SERVER_DOWN",self.name,self.id)

	event.wakeup(self.monitor)
end

local cServerChannel = channel:inherit()
function cServerChannel:disconnect()
	_serverChannel[self.id] = nil
	setChannel(self.name,nil)
	_eventListener:fireEvent("SERVER_DOWN",self.name,self.id)
end

function cServerChannel:dispatch(message,size)
	self.countor = self.countor + 1
	if self.countor == 1 then
		channel.dispatch(self,message,size)
	else
		if not self.id then
			event.error(string.format("channle:%s not register,drop message",self))
			self:close_immediately()
		else
			channel.dispatch(self,message,size)
		end
	end
end

local function onChannelAccept(_,channel)
	channel.countor = 0
end

function __init__(self)
	if env.name == "world" then
		_serverCountor = 1
	end
end

function reserveId(channel)
	assert(env.name == "world")
	local id = _serverCountor
	_serverCountor = _serverCountor + 1
	return id
end

function registerServer(channel,args)
	channel.name = args.name
	channel.id = args.id

	assert(_serverChannel[args.id] == nil)

	_serverChannel[args.id] = channel

	setChannel(args.name,channel)

	_eventListener:fireEvent("SERVER_CONNECT",args.name,args.id)

	return env.distId
end

function increaseAgent()
	assert(env.name == "world")
	env.agent_num = env.agent_num + 1
end

function increaseScene()
	assert(env.name == "world")
	env.scene_num = env.scene_num + 1
end

function agentAmount()
	assert(env.name == "world")
	local amount = 0
	for _,channel in pairs(_serverChannel) do
		if channel.name == "agent" then
			amount = amount + 1
		end
	end

	return {
		needAmount = env.agent_num,
		currAmount = amount
	}
end

function sceneAmount()
	assert(env.name == "world")
	local amount = 0
	for _,channel in pairs(_serverChannel) do
		if channel.name == "scene" then
			amount = amount + 1
		end
	end
	return amount,env.scene_num
end

function findServer(self,name)
	local result = {}
	for id,channel in pairs(_serverChannel) do
		if channel.name == name then
			result[id] = true
		end
	end
	return result
end

function listenServer(self,name)
	local listener,reason = event.listen(env[name],4,onChannelAccept,cServerChannel)
	if not listener then
		return listener,reason
	end
	event.error(string.format("%s listen success",env.name))
	return listener
end

function listenScene(self)
	local addr
	if env.scene == "ipc" then
		addr = string.format("ipc://scene%02d.ipc",env.distId)
	else
		addr = "tcp://0.0.0.0:0"
	end
	local listener,reason = event.listen(addr,4,onChannelAccept,cServerChannel)
	if not listener then
		return listener,reason
	end
	return listener
end

function connectServer(self,name,reconnect,try,addr)
	local function channelInit(channel,name)
		
		channel.monitor = event.gen_session()

		local id = channel:call("module.server_manager","registerServer",{id = env.distId,name = env.name})
		channel.id = id
		channel.name = name

		assert(_serverChannel[channel.id] == nil)

		_serverChannel[channel.id] = channel

		setChannel(channel.name,channel)

		_eventListener:fireEvent("SERVER_CONNECT",name,channel.id)
	end

	local function channelConnect(name,addr,try)
		if not addr then
			addr = env[name]
		end

		local channel,reason
		local count = 0
		while not channel do
			channel,reason = event.connect(addr,4,false,cClientChannel)
			if not channel then
				event.error(string.format("connect server:%s %s failed:%s",name,addr,reason))
				event.sleep(1)
				count = count + 1
				if try and count >= try then
					return
				end
			end
		end
		channelInit(channel,name)
		return channel
	end

	
	local channel = channelConnect(name,addr,try)
	if not channel then
		return false
	end
	if reconnect then
		event.fork(function ()
			while true do
				event.wait(channel.monitor)
				channelConnect(name,addr)
			end
		end)
	end
	return true
end

function connectServerWithAddr(self,name,addr,reconnect,try)
	return self:connectServer(name,reconnect,try,addr)
end

function registerEvent(self,ev,obj,method)
	_eventListener:registerEvent(ev,obj,method)
end

function deregisterEvent(self,ev,obj)
	_eventListener:deregisterEvent(obj,ev)
end 

-------------------------------------------------
function sendAgent(self,serverId,file,method,args,callback)
	local channel = _serverChannel[serverId]
	if not channel or channel.name ~= "agent" then
		error(string.format("sendAgent error:serverId=%d,file=%s,method=%s",serverId or -1,file,method))
	end
	channel:send(file,method,args,callback)
end

function callAgent(self,serverId,file,method,args)
	local channel = _serverChannel[serverId]
	if not channel or channel.name ~= "agent" then
		error(string.format("callAgent error:serverId=%d,file=%s,method=%s",serverId or -1,file,method))
	end
	return channel:call(file,method,args)
end

function sendScene(self,serverId,file,method,args,callback)
	local channel = _serverChannel[serverId]
	if not channel or channel.name ~= "scene" then
		error(string.format("sendScene error:serverId=%d,file=%s,method=%s",serverId or -1,file,method))
	end
	channel:send(file,method,args,callback)
end

function callScene(self,serverId,file,method,args)
	local channel = _serverChannel[serverId]
	if not channel or channel.name ~= "scene" then
		error(string.format("callScene error:serverId=%d,file=%s,method=%s",serverId or -1,file,method))
	end
	return channel:call(file,method,args)
end

function sendLogin(self,file,method,args,callback)
	if not _loginChannel then
		error(string.format("sendLogin error:serverId=%d,file=%s,method=%s",serverId or -1,file,method))
	end
	_loginChannel:send(file,method,args,callback)
end

function callLogin(self,file,method,args)
	if not _loginChannel then
		error(string.format("callLogin error:serverId=%d,file=%s,method=%s",serverId or -1,file,method))
	end
	return _loginChannel:call(file,method,args)
end

function sendWorld(self,file,method,args,callback)
	if not _worldChannel then
		error(string.format("sendWorld error:serverId=%d,file=%s,method=%s",serverId or -1,file,method))
	end
	_worldChannel:send(file,method,args,callback)
end

function callWorld(self,file,method,args)
	if not _worldChannel then
		error(string.format("callWorld error:serverId=%d,file=%s,method=%s",serverId or -1,file,method))
	end
	return _worldChannel:call(file,method,args)
end

function sendLog(self,file,method,args,callback)
	if not _loggerChannel then
		error(string.format("sendLog error:serverId=%d,file=%s,method=%s",serverId or -1,file,method))
	end
	_loggerChannel:send(file,method,args,callback)
end

function callLog(self,file,method,args)
	if not _loggerChannel then
		error(string.format("callLog error:serverId=%d,file=%s,method=%s",serverId or -1,file,method))
	end
	return _loggerChannel:call(file,method,args)
end
