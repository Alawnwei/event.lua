local event = require "event"
local mongo = require "mongo"
local model = require "model"
local helper = require "helper"
local logger = require "module.logger"
local idBuilder = import "module.id_builder"
local startup = import "server.startup"
local clientMgr = import "module.client_manager"
local fighter = import "module.scene.fighter"
local monster = import "module.scene.monster"
local sceneServer = import "module.scene.scene_server"
local itemFactory = import "module.agent.item.item_factory"
local itemContainer = import "module.agent.item.item_container"
local worldServer = import "module.world.world_server"
local scene = import "module.scene.scene"
local sceneStage = import "module.scene.scene_stage"
local skillAPI = import "module.scene.skill.skill_api"
local bullet = import "module.scene.bullet"
-- sceneServer:createScene(1001,1)

-- local userData = table.tostring({uid = 1,pos = {1,1}})
-- sceneServer:enterScene(userData,1,{1,1},false) 

-- local scene = sceneServer:getScene(1)

-- for i = 1,1 do
-- 	local inst = monster.cMonster:new(2,1,1)
-- 	scene:enter(inst,1,1)
-- end
--

local LOG = logger:create("fuck")
-- local mongodb_channel = mongo:inherit()
-- function mongodb_channel:disconnect()
-- 	os.exit(1)
-- end

-- local db_channel,reason = event.connect(env.mongodb,4,true,mongodb_channel)
-- if not db_channel then
-- 	LOG:ERROR_FM("%s connect db:%s faield:%s",env.name,env.mongodb,reason)
-- 	os.exit()
-- end



event.fork(function ()
	env.distId = 1
	_G.config = {}
	local data = loadfile("./config/item.lua")()
	_G.config["item"] = data
	startup.run(1,env.distId,false,env.mongodb)
	idBuilder:init(env.serverId,1)
	local container = itemContainer.cItemContainer:load(nil,model.get_dbChannel(),"user",{userUid = 5})
	if not container then
		container = itemContainer.cItemContainer:new()
	end
	table.print(container.bagMgr.itemSlot)
	for uid,item in pairs(container.bagMgr.itemSlot) do
		print(item:getType())
	end

	container:insertItemByCid(100,1)
	-- container:deleteItemByCid(100,5)
	container:insertItemByCid(101,1)
	-- container:insertItemByCid(2000,1)
	container:save(model.get_dbChannel(),"user",{userUid = 5})
	-- table.print(container)

	-- worldServer:enter(1,1)
	-- worldServer:leave(1)

	-- local sceneInst = sceneStage.cSceneStage:new()
	-- sceneInst:onCreate(1,1001,1)
	-- sceneInst:enterArea(1)

	-- local monsterObj = sceneInst:spawnMonster(1,{100,100},{1,0})
	-- local monsterObj = sceneInst:spawnMonster(1,{100,100},{1,0})

	-- -- local fighter = fighter.cFighter:new()
	-- -- fighter:onCreate(nil,{100,100})
	-- -- print("fighter.uid",fighter.uid)
	-- -- model.bind_fighter_with_uid(fighter.uid,fighter)
	-- -- sceneInst:enter(fighter,{120,120})

	-- LOG:DEBUG_FM("%s connect db:%s ",env.name,env.mongodb)
	-- LOG:INFO_FM("%s connect db:%s ",env.name,env.mongodb)
	-- LOG:WARN_FM("%s connect db:%s ",env.name,env.mongodb)
	-- LOG:ERROR_FM("%s connect db:%s ",env.name,env.mongodb)
end)

