local event = require "event"
local model = require "model"
local timer = require "timer"
local scene = import "module.scene.scene"
local idBuilder = import "module.id_builder"
import "handler.cmd_handler"


_sceneCtx = _sceneCtx or {}
_sceneMap = _sceneMap or {}

function __init__(self)
	
end

function start()

end

function flush()
	local all = model.fetch_fighter()
	for _,fighter in pairs(all) do
		fighter:save()
	end
end

function onClientData(_,args)
	local user = model.fetch_fighter_with_cid(args.cid)
	local reader = protocol.reader[args.messageId] 
	if not reader then
		event.error(string.format("no such pto id:%d",args.messageId))
		return
	end
	reader(user or args.cid,args.data)
end

function createScene(self,args)
	local sceneId,sceneUid = args.sceneId,args.sceneUid

	local sceneInfo = _sceneCtx[sceneId]
	if not sceneInfo then
		sceneInfo = {}
		_sceneCtx[sceneId] = sceneInfo 
	end

	local scene = scene.cScene:new(sceneId,sceneUid)
	sceneInfo[sceneUid] = scene
	_sceneMap[sceneUid] = scene	
	return sceneUid
end

function deleteScene(self,sceneUid)
	local scene = _sceneMap[sceneUid]
	scene:release()
	_sceneMap[sceneUid] = nil	

	local sceneInfo = _sceneCtx[scene.sceneId]
	sceneInfo[sceneUid] = nil
end

function getScene(self,sceneUid)
	return _sceneMap[sceneUid]	
end

function enterScene(self,userData,sceneUid,pos,switch)
	local fighter = class.instanceFrom("fighter",table.decode(userData))
	fighter:create(fighter.uid,fighter.pos[1],fighter.pos[2])
	model.bind_fighter_with_uid(fighter.uid,fighter)

	local scene = self:getScene(sceneUid)
	assert(scene ~= nil,sceneUid)
	scene:enter(fighter,pos)
end

function leaveScene(self,userUid,switch)
	local fighter = model.fetch_fighter_with_uid(userUid)
	model.unbind_fighter_with_uid(fighter)

	local scene = self:getScene(fighter.sceneUid)
	scene:leave(fighter)
	fighter:save()
	
	local dbChannel = model.get_dbChannel()
	local updater = {}
	updater["$inc"] = {version = 1}
	updater["$set"] = {time = os.time()}
	dbChannel:findAndModify("scene_user","save_version",{query = {uid = sceneUid.uid},update = updater,upsert = true})

	local fighterData 
	if switch then
		fighterData = fighter:packData()
	end

	fighter:release()

	return fighterData 
end

function transferInside(self,userUid,sceneUid,pos)
	local fighter = model.fetch_fighter_with_uid(userUid)

	local scene = self:getScene(fighter.sceneUid)
	scene:leave(fighter)

	local scene = self:getScene(sceneUid)
	scene:enter(fighter,pos)
end
