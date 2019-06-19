local event = require "event"
local cjson = require "cjson"
local model = require "model"
local util = require "util"
local chatMgr = import "module.world.chat_manager"
local serverMgr = import "module.server_manager"
local dbObject = import "module.database_object"

cChatUser = dbObject.cCollection:inherit("chatUser")

function __init__(self)
	self.cChatUser:saveField("chatInfo")
end


function cChatUser:onCreate(user)
	self.__user = user
end

function cChatUser:onDestroy()
end


function cChatUser:onEnter()
	if not self.chatInfo then
		self.chatInfo = {}
	end
	self:markDirty("chatInfo")
	chatMgr:enter(self)
end

function cChatUser:onOverride()
	chatMgr:override(self)
end

function cChatUser:onLeave()
	chatMgr:leave(self)
end

