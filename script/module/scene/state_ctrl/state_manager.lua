local util = require "util"
local object = import "module.object"


local eState = {
	["IDLE"] = import("module.scene.state_ctrl.idle_state").cStateIdle,
	["MOVE"] = import("module.scene.state_ctrl.move_state").cStateMove,
	["SKILL"] = import("module.scene.state_ctrl.skill_state").cStateSkill,
	["HIT_BACK"] = import("module.scene.state_ctrl.hitback_state").cStateHitBack,
	["HIT_FLY"] = import("module.scene.state_ctrl.hitfly_state").cStateHitFly,
}

cStateMgr = object.cObject:inherit("stateMgr")


function cStateMgr:ctor(sceneObj)
	self.stateMgr = {}
	self.owner = sceneObj
end

function cStateMgr:onCreate()
end

function cStateMgr:onDestroy()

end

function cStateMgr:onUpdate(now)
	local removeList = {}
	for stateType,stateObj in pairs(self.stateMgr) do
		local isRemove = stateObj:onUpdate(now)
		if isRemove then
			table.insert(removeList,stateType)
		end
	end

	for _,stateType in pairs(removeList) do
		local stateObj = self.stateMgr[stateType]
		stateObj:release()
		self.stateMgr[stateType] = nil
	end
end

function cStateMgr:hasState(stateType)
	return self.stateMgr[stateType] ~= nil
end

function cStateMgr:canAddState(stateType)
	return true
end

function cStateMgr:addState(stateType,stateData)
	if not self:canAddState(stateType) then
		return false
	end
	local stateObj = eState[stateType]:new(self.owner,stateData)
	stateObj:onCreate()
	self.stateMgr[stateType] = stateObj
end

function cStateMgr:delState(stateType)
	local stateObj = self.stateMgr[stateType]
	if stateObj then
		stateObj:release()
		self.stateMgr[stateType] = nil
	end
end

function cStateMgr:replaceState(stateType,stateData)

end