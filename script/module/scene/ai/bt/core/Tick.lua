local object = import "module.object"

btTick = {}

function btTick.create()
	local ctx = {}
	ctx.tree = nil
	ctx.debug = nil
	ctx.target = nil
	ctx.blackboard = nil

	ctx._openNodes = {}
	ctx._nodeCount = 0
	return ctx
end

function btTick.enterNode(ctx, node)
	ctx._nodeCount = ctx._nodeCount + 1
	table.insert(ctx._openNodes, node)
end

function btTick.openNode(ctx, node)
	-- print("open",node.title)
end

function btTick.tickNode(ctx, node)
	print("tick",node.title)
end

function btTick.closeNode(ctx, node)
	-- print("close",node.title)
	table.remove(ctx._openNodes)
end

function btTick.exitNode(ctx, node)
end