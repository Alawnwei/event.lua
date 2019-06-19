local sceneConst = import "module.scene.scene_const"
local scene = import "module.scene.scene"

cSceneStage = scene.cScene:inherit("scene_stage")

function cSceneStage:onCreate(stageId,sceneId,sceneUid)
	super(cSceneStage).onCreate(self,sceneId,sceneUid)
	self.stageId = stageId

	self:start()
end

local areaCfg = {
	[sceneConst.eSCENE_AREA_EVENT.SpawnMonster] = {
		{
			monsterId = 1,
			pos = {100,100},
			range = 20,
			posRandom = 1,
			amount = 1,
		}, {
			monsterId = 2,
			pos = {150,150},
			range = 20,
			posRandom = 1,
			amount = 1,
		}
	}
}

function cSceneStage:onStart()
	self:initArea(1,areaCfg)

	self:addPassEvent(sceneConst.eSCENE_PASS_EVENT.MONSTER_DIE,1)
	
	self:addFailEvent(sceneConst.eSCENE_FAIL_EVENT.TIMEOUT, 300)
	self:addFailEvent(sceneConst.eSCENE_FAIL_EVENT.USER_ACE)
end

function cSceneStage:onOver()

end

function cSceneStage:onWin()

end

function cSceneStage:onFail()

end

function cSceneStage:onUserEnter(user)
	print("onUserEnter",user.uid)
	super(cSceneStage).onUserEnter(self,user)
end

function cSceneStage:onUserLeave(user)
	super(cSceneStage).onUserLeave(self,user)
end

function cSceneStage:onObjEnter(obj)
	print("onObjEnter",obj.uid)
end

function cSceneStage:onObjLeave(obj)

end