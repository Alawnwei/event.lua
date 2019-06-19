local event = require "event"
local cjson = require "cjson"
local model = require "model"
local util = require "util"
local protocol = require "protocol"
local server_manager = import "module.server_manager"
local dbObject = import "module.database_object"
local chatUser = import "module.world.chat_user"
local teamUser = import "module.world.team_user"

cWorldUser = dbObject.cDatabase:inherit("worldUser","uid","cid")

function __init__(self)
	self.cWorldUser:saveField("chatUser")
	self.cWorldUser:saveField("teamUser")
	self.cWorldUser:saveField("fighter")
end


function cWorldUser:onCreate(userUid,agentId)
	self.userUid = userUid
	self.agentId = agentId
end

function cWorldUser:onDestroy()
end

function cWorldUser:dbIndex()
	return {userUid = self.userUid}
end

function cWorldUser:enter()
	event.error(string.format("user:%d enter world:%d",self.userUid,env.distId))

	if not self.chatUser then
		self.chatUser = chatUser.cChatUser:new()
		self:init(self.chatUser)
	end
	self.chatUser:onCreate(self)
	self.chatUser:onEnter()

	if not self.teamUser then
		self.teamUser = teamUser.cTeamUser:new()
		self:init(self.teamUser)
	end
	self.teamUser:onCreate(self)
	self.teamUser:onEnter()
end

function cWorldUser:override(agentId)
	self.agentId = agentId
	self.chatUser:onOverride()
	self.teamUser:onOverride()
end

function cWorldUser:leave()
	event.error(string.format("user:%d leave world:%d",self.userUid,env.distId))

	self.chatUser:onLeave()
	self.teamUser:onLeave()
end

