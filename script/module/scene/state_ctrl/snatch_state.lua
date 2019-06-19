local util = require "util"
local event = require "event"

local stateBase = import "module.scene.state_ctrl.state_base"
local skillApi = import "module.scene.skill.skill_api"

cStateSnatch = stateBase.cStateBase:inherit("snatchState")

function cStateSnatch:ctor(sceneObj,info)
	local now = event.now()
	self.startTime = now
	self.overTime = now + info.interval
	self.distance = info.distance
	self.owner = sceneObj
end

function cStateSnatch:onCreate()
end

function cStateSnatch:onDestroy()
	
end

function cStateSnatch:onUpdate(now)
	local now = now or event.now()
	return now >= self.overTime
end




