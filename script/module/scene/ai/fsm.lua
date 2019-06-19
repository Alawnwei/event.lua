local util = require "util"

local object = import "module.object"

cFSM = object.cObject:inherit("aiFSM")

local eAI_STATE = {
	["IDLE"] 	= import("module.scene.ai.state.ai_idle").cAIIdle,
	["PATROL"] 	= import("module.scene.ai.state.ai_patrol").cAIPatrol,
	["GOHOME"] 	= import("module.scene.ai.state.ai_gohome").cAIGohome,
	["FOLLOW"] 	= import("module.scene.ai.state.ai_follow").cAIFollow,
	["ATTACK"] 	= import("module.scene.ai.state.ai_attack").cAIAttack,
}

function cFSM:ctor(charactor,debug)
	self.charactor = charactor
	self.aiState = nil
	self.debug = debug or false
end

function cFSM:onCreate()
end

function cFSM:onDestroy()

end

function cFSM:switchState(state,...)
	if self.aiState then
		if self.debug then
			print(string.format("ai[%d] leave:%s",self.charactor.owner.uid,self.aiState.__name))
		end

		self.aiState:onLeave()
		self.aiState:release()
	end

	self.aiState = eAI_STATE[state]:new(self)
	self.aiState:onCreate(...)

	if self.debug then
		print(string.format("ai[%d] enter:%s",self.charactor.owner.uid,self.aiState.__name))
	end
	self.aiState:onEnter()
end

function cFSM:onUpdate(now)
	if self.aiState then
		if self.debug then
			print(string.format("ai[%d] update:%s",self.charactor.owner.uid,self.aiState.__name))
		end
		self.aiState:onUpdate(now)
	end
end
