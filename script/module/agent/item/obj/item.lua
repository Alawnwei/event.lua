local idBuilder = import "module.id_builder"
local object = import "module.object"


cItem = object.cObject:inherit("item","uid")

function __init__(self)
	self.cItem:saveField("uid")
	self.cItem:saveField("cid")
	self.cItem:saveField("amount")
	self.cItem:saveField("__name")
end

function cItem:onCreate(cid,amount)
	self.cid = cid
	self.amount = amount
end

function cItem:onDestroy()

end

function cItem:canUse()

end

function cItem:use(user)
	
end

function cItem:canOverlapByCid(cid,amount)
	if self.cid ~= cid then
		return false,amount
	end
	local cfg = config.item[cid]
	if not cfg.overlap or cfg.overlap == 0 then
		return true
	end

	local total = self.amount + amount
	if total > cfg.overlap then
		return false,total - cfg.overlap
	end
	return true
end

function cItem:canOverlapBy(item)
	local more = self:overlapMore()
	if more == 0 then
		return false
	end
	if self.cid ~= item.cid then
		return false
	end
	return true
end

function cItem:overlapBy(item)
	if not self:canOverlapBy(item) then
		return
	end

	local more = self:overlapMore()
	if item.amount > more then
		self.amount = self.amount + more
		item.amount = item.amount - more
	else
		self.amount = self.amount + item.amount
		item.amount = 0
	end
end

function cItem:overlapMore()
	local cfg = config.item[self.cid]
	if cfg.overlap == 1 then
		return 0
	end
	if cfg.overlap <= self.amount then
		return 0
	end
	return cfg.overlap - self.amount
end

function cItem:getBaseInfo()
	return {cid = self.cid,uid = self.uid,amount = self.amount}
end

function cItem:getExtraInfo()

end
