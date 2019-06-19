local util = require "util"
local event = require "event"

local stateBase = import "module.scene.state_ctrl.state_base"
local skillApi = import "module.scene.skill.skill_api"

cStateHitBack = stateBase.cStateBase:inherit("stateHitBack")

local moveTorward = util.move_torward

function cStateHitBack:ctor(sceneObj,hitBackInfo)
	self.lastTime = event.now()
	
	self.startTime = hitBackInfo.startTime
	self.overTime = hitBackInfo.overTime
	self.speed = hitBackInfo.speed
	self.angle = hitBackInfo.angle

	self.owner = sceneObj
end

function cStateHitBack:onCreate()
end

function cStateHitBack:onDestroy()
	
end

function cStateHitBack:onUpdate(now)
	local now = now or event.now()

	local flyOver = false
	local dtTime
	if now >= self.overTime then
		dtTime = self.overTime - self.lastTime
		flyOver = true
	else
		dtTime = now - self.lastTime
	end

	local opos = self.owner.pos

	local dtFly = self.speed * dtTime

	local nx,nz = moveTorward(opos[1],opos[2],self.angle,dtFly)

	self.owner:move(nx,nz)
	
	self.lastTime = now

	return flyOver
end




