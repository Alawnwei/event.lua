local util = require "util"
local event = require "event"
local stateBase = import "module.scene.state_ctrl.state_base"
local skillApi = import "module.scene.skill.skill_api"

cStateSkill = stateBase.cStateBase:inherit("stateSkill")

function cStateSkill:ctor(sceneObj,skillInfo)
	self.skillId = skillInfo.skillId
	self.skillInfo = skillInfo
	self.startTime = event.now()
	self.overTime = self.startTime + skillInfo.interval
	self.attacker = sceneObj
	skillApi:onSkillBegin(sceneObj,self.skillId,skillInfo)
end

function cStateSkill:onCreate()
end

function cStateSkill:onDestroy()
	skillApi:onSkillEnd(sceneObj,self.skillId,skillInfo)
end

function cStateSkill:onUpdate(now)
	local now = now or event.now()

	local interval = (now - self.startTime) / 1000

	local skillOver = true

	for i = self.skillInfo.hitIndex, #self.skillInfo.hitInfo do
		
		local info = self.skillInfo.hitInfo[i]
		
		if interval >= info.time then
			skillApi:onSkillExecute(self.attacker,self.skillId,self.skillInfo,info)
		else
			skillOver = false
			self.skillInfo.hitIndex = i
			break
		end
	end

	if skillOver then
		return true
	end

	return false
end




