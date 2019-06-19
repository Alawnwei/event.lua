local util = require "util"
local event = require "event"

local aiState = import "module.scene.ai.state.ai_state"

cAIAttack = aiState.cAIState:inherit("aiAttack")

function cAIAttack:onCreate(targetObjUid)
	self.targetObjUid = targetObjUid
end

function cAIAttack:onEnter()
	self.time = event.now()
end

function cAIAttack:onExecute(now)
	if now - self.time >= 5000 then
		self.fsm:switchState("GOHOME")
		return false
	end
	return true
end
