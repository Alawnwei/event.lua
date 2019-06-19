local event = require "event"
local cjson = require "cjson"
local model = require "model"
local util = require "util"
local serverMgr = import "module.server_manager"
local dbObject = import "module.database_object"

cTeamUser = dbObject.cCollection:inherit("teamUser")

function __init__(self)
	self.cTeamUser:saveField("teamInfo")
end


function cTeamUser:onCreate(user)
	self.__user = user
end

function cTeamUser:onDestroy()
end


function cTeamUser:onEnter()
	if not self.teamInfo then
		self.teamInfo = {}
	end
	self:markDirty("teamInfo")
end

function cTeamUser:onOverride()

end

function cTeamUser:onLeave()

end

