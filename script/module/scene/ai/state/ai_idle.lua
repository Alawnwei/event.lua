local util = require "util"
local event = require "event"

local aiState = import "module.scene.ai.state.ai_state"

cAIIdle = aiState.cAIState:inherit("aiIdle")

function cAIIdle:onCreate(...)
	self.switchPatrolTime = 1000
end

function cAIIdle:onEnter()
	self.time = event.now()
end

function cAIIdle:onExecute(now)
	if self.charactor:haveEnemy() then
		self.fsm:switchState("FOLLOW")
		return false
	else
		if now - self.time > self.switchPatrolTime then
			self.fsm:switchState("PATROL")
			return false
		end
	end
	return true
end
