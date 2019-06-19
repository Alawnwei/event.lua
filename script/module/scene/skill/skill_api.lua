local event = require "event"


eATTACK_BOX = {
	["CIRCLE"] = 1,
	["SECTOR"] = 2,
	["RECTANGLE"] = 3,
}

eSKILL_EVENT = {
	["DAMAGE"] 				= 1,
	["ADD_SELF_BUFFER"] 	= 2,
	["DEL_SELF_BUFFER"] 	= 3,
	["ADD_OTHER_BUFFER"] 	= 4,
	["DEL_OTHER_BUFFER"] 	= 5,
	["HIT_FLY"] 			= 6,
	["HIT_BACK"] 			= 7,
}

local hitInfo = {
		[1] = {
			time = 1,
			event = { [eSKILL_EVENT.DAMAGE] = {},
					  [eSKILL_EVENT.ADD_SELF_BUFFER] = {bufferId = 1}},
			atkBox = { boxType = eATTACK_BOX.SECTOR,range = 100,degree = 60 }
		},
		[2] = { 
			time = 1.5,
			event = { [eSKILL_EVENT.DAMAGE] = {},
					  [eSKILL_EVENT.HIT_FLY] = {time = 1} },
			atkBox = {boxType = eATTACK_BOX.RECTANGLE,length = 100,width = 20}
		},
		[3] = { 
			time = 2.0,
			event = { [eSKILL_EVENT.DAMAGE] = {},
					  [eSKILL_EVENT.HIT_BACK] = {time = 0.5,speed = 10,angle = 60},
					  [eSKILL_EVENT.DEL_SELF_BUFFER] = {bufferId = 1}, },
			atkBox = {boxType = eATTACK_BOX.CIRCLE,range = 100}
		} }

function useSkill(self, attacker, skillId)

	local skillInfo = {
		skillId = skillId,
		hitIndex = 1,
		hitInfo = hitInfo,
		interval = 2.5
	}

	local stateMgr = attacker.stateMgr
	stateMgr:addState("SKILL",skillInfo)
end

function onSkillBegin(self, attacker, skillInfo)
	print("onSkillBegin")
end

function onSkillEnd(self, attacker, skillInfo)
	print("onSkillEnd")
end

function onSkillExecute(self, attacker, skillId, skillInfo, hitInfo)
	print("onSkillExecute")

	local hitterObjs = self:selectHitter(attacker,skillInfo,hitInfo.atkBox)

	for evType,evInfo in pairs(hitInfo.event) do

		if evType == eSKILL_EVENT.DAMAGE then
			for _,hitterObj in pairs(hitterObjs) do
				self:onDamage(attacker,hitterObj,hitInfo)
			end

		elseif evType == eSKILL_EVENT.ADD_SELF_BUFFER then
			self:onAddBuff(attacker,evInfo.bufferId)

		elseif evType == eSKILL_EVENT.DEL_SELF_BUFFER then
			self:onDelBuff(attacker,evInfo.bufferId)

		elseif evType == eSKILL_EVENT.HIT_FLY then
			for _,hitterObj in pairs(hitterObjs) do
				self:onHitFly(attacker,hitterObj,evInfo)
			end

		elseif evType == eSKILL_EVENT.HIT_BACK then
			for _,hitterObj in pairs(hitterObjs) do
				self:onHitBack(attacker,hitterObj,evInfo)
			end
			
		end
	end


end

function selectHitter(self,attacker,skillInfo,atkBoxInfo)

	local resultObjs
	if atkBoxInfo.boxType == eATTACK_BOX.CIRCLE then
		resultObjs = attacker:getObjInCircle(attacker.pos,atkBoxInfo.range)
	elseif atkBoxInfo.boxType == eATTACK_BOX.SECTOR then
		resultObjs = attacker:getObjInSector(attacker.pos,attacker.face,atkBoxInfo.degree,atkBoxInfo.range)
	elseif atkBoxInfo.boxType == eATTACK_BOX.RECTANGLE then
		resultObjs = attacker:getObjInRectangle(attacker.pos,attacker.face,atkBoxInfo.length,atkBoxInfo.width)
	end

	return resultObjs
end


function calcDamage(self,attacker,hitter)

end

function onDamage(self,attacker,hitter)
	local damage = self:calcDamage(attacker,hitter)

	-- hitter:onDamage(damage)
end

function onHitFly(self,attacker,hitter,hitInfo)
	local hitterStateMgr = hitter.stateMgr
	if hitterStateMgr:hasState("MOVE") then
		hitterStateMgr:delState("MOVE")
	end

	if hitterStateMgr:hasState("HIT_BACK") then
		return
	end

	if hitterStateMgr:hasState("HIT_FLY") then
		return
	end

	hitterStateMgr:addState("HIT_FLY",{time = hitInfo.time})
end

function onHitBack(self,attacker,hitter)
	local hitterStateMgr = hitter.stateMgr
	if hitterStateMgr:hasState("MOVE") then
		hitterStateMgr:delState("MOVE")
	end

	if hitterStateMgr:hasState("HIT_BACK") then
		return
	end

	if hitterStateMgr:hasState("HIT_FLY") then
		return
	end

	local flyInfo = {startTime = event.now(),
				     overTime = event.now() + hitInfo.time,
					 speed = hitInfo.speed,
					 angle = hitInfo.angle}

	hitterStateMgr:addState("HIT_BACK",flyInfo)
end

function onAddBuff(self,targetObj,bufferId)

end

function onDelBuff(self,targetObj,bufferId)

end