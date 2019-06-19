local idBuilder = import "module.id_builder"
local itemFactory = import "module.agent.item.item_factory"
local itemMgr = import "module.agent.item.item_manager"

cCurrencyMgr = itemMgr.cItemMgr:inherit("currencyMgr")

function __init__(self)
end


function cCurrencyMgr:onCreate(...)
	itemMgr.cItemMgr.onCreate(self)
end

function cCurrencyMgr:onDestroy()
	itemMgr.cItemMgr.onDestroy(self)
end
