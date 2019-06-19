local idBuilder = import "module.id_builder"
local common = import "common.common"
local object = import "module.object"
local itemFactory = import "module.agent.item.item_factory"
local currencyMgr = import "module.agent.item.currency_manager"
local bagMgr = import "module.agent.item.bag_manager"
local petMgr = import "module.agent.item.pet_manager"
local equipmentMgr = import "module.agent.item.equipment_manager"

cItemContainer = object.cObject:inherit("item_container")

function __init__(self)
	self.cItemContainer:saveField("currencyMgr")
	self.cItemContainer:saveField("bagMgr")
	self.cItemContainer:saveField("petMgr")
	self.cItemContainer:saveField("equipmentMgr")

end


function cItemContainer:onCreate()

end

function cItemContainer:onDestroy()

end

function cItemContainer:markDirty(field)
	self.__dirty[field] = true
	if self.__dbObject then
		self.__dbObject:markDirty(self.__name)
	end
end

function cItemContainer:load(parent,dbChannel,db,dbIndex)
	local inst = self:new()
	for field in pairs(self.__saveFields) do
		if field ~= "__name" then
			local result
			local cls = class.get(field)
			assert(cls ~= nil,field)
			local result = cls:load(inst,dbChannel,db,dbIndex)
			if result then
				inst[field] = result
			else
				result = cls:new()
				result:attachDb(inst)
				inst[field] = result
			end
			result:onCreate()
		end
	end
	inst.__dbObject = parent
	return inst
end

function cItemContainer:save(dbChannel,db,dbIndex)
	
	for field in pairs(self.__dirty) do
		if self.__saveFields[field] ~= nil then
			local inst = self[field]
			inst:save(dbChannel,db,dbIndex)
		end
	end
	self.__dirty = {}
end

function cItemContainer:onEnterGame(user)
	self.currencyMgr:onEnterGame(user)
	self.bagMgr:onEnterGame(user)
	self.petMgr:onEnterGame(user)
	self.equipmentMgr:onEnterGame(user)
end

function cItemContainer:onLeaveGame()
	self.currencyMgr:onLeaveGame()
	self.bagMgr:onLeaveGame()
	self.petMgr:onLeaveGame()
	self.equipmentMgr:onLeaveGame()
end

function cItemContainer:onOverride(user)
	self.currencyMgr:onOverride(user)
	self.bagMgr:onOverride(user)
	self.petMgr:onOverride(user)
	self.equipmentMgr:onOverride(user)
end

function cItemContainer:onSyncInfo()
	self.currencyMgr:onSyncInfo()
	self.bagMgr:onSyncInfo()
	self.petMgr:onSyncInfo()
	self.equipmentMgr:onSyncInfo()
end


function cItemContainer:getItem(itemUid)
	local item = model.fetch_item_with_uid(itemUid)

	-- for field in pairs(self.__saveFields) do
	-- 	local inst = self[field]
	-- 	if inst then
	-- 		local item = inst:getItem(itemUid)
	-- 		if item then
	-- 			return item
	-- 		end
	-- 	end
	-- end
	return item
end

function cItemContainer:insertItemByCid(cid,amount)
	local cfg = config.item[cid]
	local bagType = common.eITEM_CATEGORY_BAG[cfg.category]
	local bagInst = self[bagType]
	bagInst:insertItemByCid(cid,amount)
end

function cItemContainer:insertItem(item)
	local cfg = config.item[item.cid]
	local bagType = common.eITEM_CATEGORY_BAG[cfg.category]
	local bagInst = self[bagType]
	bagInst:insertItem(item)
end

function cItemContainer:deleteItem(item,amount)
	local cfg = config.item[item.cid]
	local bagType = common.eITEM_CATEGORY_BAG[cfg.category]
	local bagInst = self[bagType]
	bagInst:deleteItem(item)
end

function cItemContainer:deleteItemByCid(cid,amount)
	local cfg = config.item[cid]
	local bagType = common.eITEM_CATEGORY_BAG[cfg.category]
	local bagInst = self[bagType]
	bagInst:deleteItemByCid(cid,amount)
end

function cItemContainer:deleteItemByUid(uid,amount)
	local item = self:getItem(uid)
	self:deleteItem(item,amount)
end

function cItemContainer:itemEnough(cid,amount)
	local cfg = config.item[cid]
	local bagType = common.eITEM_CATEGORY_BAG[cfg.category]
	local bagInst = self[bagType]
	return bagInst:itemEnough(cid,amount)
end

function cItemContainer:useItem(itemUid,amount)

end
