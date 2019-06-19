local util = require "util"
local event = require "event"

local stateBase = import "module.scene.state_ctrl.state_base"
local skillApi = import "module.scene.skill.skill_api"

cStateHitFly = stateBase.cStateBase:inherit("stateHitFly")

function cStateHitFly:ctor(sceneObj,hitFlyInfo)
	self.overTime = event.now() + hitFlyInfo.time
	self.owner = sceneObj
end

function cStateHitFly:onCreate()
end

function cStateHitFly:onDestroy()
	
end

function cStateHitFly:onUpdate(now)
	local now = now or event.now()
	return now >= self.overTime
end




