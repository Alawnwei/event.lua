local bt = import "module.scene.ai.bt.core.BehaviorTree"
local btTick = import "module.scene.ai.bt.core.Tick".btTick
local btBlackboard = import "module.scene.ai.bt.core.Blackboard".btBlackboard

local kEXPAND_NUM = 50

local kAI_PATH = "./config/"

function __init__(self)
	self.__allBTreeObjs = self.__allBTreeObjs or {}  -- 行为树池
end


function createTreeById(self, aiName, aiTarget)

	while true do
		local poolObjs = self.__allBTreeObjs[aiName] or {}
		local treeObj = table.remove(poolObjs)
		if not treeObj then
			self:expandTree(aiName)
		else
			treeObj.tick = btTick.create()
			treeObj.tick.tree = treeObj
			treeObj.tick.target = aiTarget
			treeObj.tick.blackboard = btBlackboard.create()
			return treeObj
		end
	end
end

function addToPool(self, aiName,treeObj)
	treeObj.tick.tree = nil
	treeObj.tick.target = nil
	treeObj.tick.blackboard = nil
	treeObj.tick = nil
	local poolObjs = self.__allBTreeObjs[aiName]
	table.insert(poolObjs, treeObj)
end

function expandTree(self, aiName)
	local poolObjs = self.__allBTreeObjs[aiName] or {}

	local path = kAI_PATH..aiName..".lua"

	local FILE = io.open(path,"r")
	local data = FILE:read("*a")
	FILE:close()

	local cfg = load(data)()

	for i = 1,kEXPAND_NUM do
		local tree = bt.cBtTree:new(cfg.title,cfg.description)
		tree:load(cfg)
		table.insert(poolObjs,tree)
	end

	self.__allBTreeObjs[aiName] = poolObjs
end
