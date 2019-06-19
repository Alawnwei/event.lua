local util = require "util"
local model = require "model"
local event = require "event"

local aiState = import "module.scene.ai.state.ai_state"

cAIFollow = aiState.cAIState:inherit("aiFollow")

function cAIFollow:onCreate(...)
	self.following = false
	self.followCheckTime = 1000
end

function cAIFollow:onEnter()
	local enemyUid = self.charactor:searchEnemy()
	if not enemyUid then
		self.fsm:switchState("IDLE")
		return false
	end

	self.lockEnemyUid = enemyUid

	if not self.charactor:moveToTarget(enemyUid) then
		self.following = false
		return false
	end

	self.following = true

	self.followTime = event.now()

	return true
end

function cAIFollow:onExecute(now)
	local enemyObj = model.fetch_fighter_with_uid(self.lockEnemyUid)
	if not enemyObj or enemyObj.isDead then
		self.fsm:switchState("IDLE")
		return false
	end

	if not self.following then
		if not self.charactor:moveToTarget(self.lockEnemyUid) then
			return false
		end

		self.following = true
		self.followTime = now

		return true
	end

	if self.charactor:isOutOfRange() then
		self.fsm:switchState("GOHOME")
		return false
	end

	if self.charactor:canAttack(enemyObj) then
		self.fsm:switchState("ATTACK",self.lockEnemyUid)
		return false
	end

	local dtTime = now - self.followTime
	if dtTime >= self.followCheckTime then
		self.followTime = now

		if not self.charactor:moveToTarget(self.lockEnemyUid) then
			self.following = false
			return false
		end 
	end

	return true
end
