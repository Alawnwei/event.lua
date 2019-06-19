local idBuilder = import "module.id_builder"
local itemFactory = import "module.agent.item.item_factory"
local itemMgr = import "module.agent.item.item_manager"

cPetMgr = itemMgr.cItemMgr:inherit("petMgr")

function __init__(self)
end

function cPetMgr:onCreate(...)
	itemMgr.cItemMgr.onCreate(self)
end

function cPetMgr:onDestroy()
	itemMgr.cItemMgr.onDestroy(self)
end

