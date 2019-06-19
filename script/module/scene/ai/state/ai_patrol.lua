local util = require "util"
local model = require "model"
local event = require "event"
local aiState = import "module.scene.ai.state.ai_state"

cAIPatrol = aiState.cAIState:inherit("aiPatrol")

function cAIPatrol:onCreate(...)

end

function cAIPatrol:doPatrol()
	local ownerObj = self.charactor.owner
	local stateMgr = ownerObj.stateMgr
	if not stateMgr:canAddState("MOVE") then
		return false
	end

	self.patrolPos = {self.charactor:randomPatrolPos()}

	local moveCtrl = ownerObj.moveCtrl

	moveCtrl:onServerMoveStart({{ownerObj.pos[1],ownerObj.pos[2]}, self.patrolPos})
end

function cAIPatrol:onEnter()
	return self:doPatrol()
end

function cAIPatrol:onExecute(now)
	if not self.patrolPos then
		self:doPatrol()
	end

	if self.charactor:haveEnemy() then
		self.fsm:switchState("FOLLOW")
		return false
	end

	local ownerObj = self.charactor.owner
	local stateMgr = ownerObj.stateMgr

	if not stateMgr:hasState("MOVE") then
		self.fsm:switchState("IDLE")
		return false
	end
	return true
end
