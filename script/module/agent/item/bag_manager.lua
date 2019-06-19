local idBuilder = import "module.id_builder"
local itemFactory = import "module.agent.item.item_factory"
local itemMgr = import "module.agent.item.item_manager"

cBagMgr = itemMgr.cItemMgr:inherit("bagMgr")

function __init__(self)
	self.cBagMgr:saveField("gridMax")
end


function cBagMgr:onCreate(...)
	itemMgr.cItemMgr.onCreate(self)
	self.gridMax = 30
	self:markDirty("gridMax")
end

function cBagMgr:onDestroy()
	itemMgr.cItemMgr.onDestroy(self)
end

function cBagMgr:canInsertList(list)
	local total = 0
	for cid,amount in pairs(list) do
		local count = self:needGridCount(cid,amount)
		total = total + count
	end
	if total + self:getGridCount() > self.gridMax then
		return false
	end
	return true
end

function cBagMgr:canInsert(cid,amount)
	local count = self:needGridCount(cid,amount)
	if count + self:getGridCount()  > self.gridMax then
		return false
	end
	return true
end

function cBagMgr:unlockGrid()

end
