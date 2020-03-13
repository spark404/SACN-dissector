sacn_proto = Proto("sacn", "sAcn")

-- UDP and TCP Dissector Tables
udp_table = DissectorTable.get("udp.port")
tcp_table = DissectorTable.get("tcp.port")

--Globals
sacn_rootlayer_size = 38

function sacn_proto.dissector(buffer, pinfo, tree)
	if (buffer:len() < sacn_rootlayer_size) then
		pinfo.desegment_len = sacn_rootlayer_size - buffer:len()
		return
	end

	pinfo.cols.protocol = "sAcn"
	pinfo.cols.info = string.format("sAcn >")

	subtree = tree:add(sacn_proto, buffer(), string.format("E1.31 (sACN) Length: %d", buffer:len()))

	-- Add the root layer
	start = 0
	preamblesize  = buffer(start,2):uint()
	postamblesize = buffer(start+2,2):uint()
	flength       = buffer(start+16, 2):uint()
	flags         = bit.rshift(flength, 12)
	length        = bit.band(flength, 0x0fff)

	-- Now we can check if we got everything
	packetsize = preamblesize + postamblesize + length
	if (buffer:len() < packetsize) then
		pinfo.desegment_len = packetsize - buffer:len()
		return
	end

	local root_layer = ProtoField.uint8("acn.root", "sacn_rootlayer")
	rootree = subtree:add(root_layer, buffer(0, packetsize), "Acn Root Layer", packetsize)

	rootree:add(buffer(start, 2), "Preamble Size: " .. preamblesize)
	rootree:add(buffer(start+2, 2), "Postamble Size: " .. postamblesize)
	rootree:add(buffer(start+4, 12), "ACN Pid: " .. buffer(start+4,12):string())
	
	rootree:add(buffer(start+16, 2), "Flags: " .. flags)
	rootree:add(buffer(start+16, 2), "Length: " .. length)

	rootree:add(buffer(start+18, 4), "Layer Vector: " .. buffer(start+18,4):uint())
	rootree:add(buffer(start+22, 16), "Cid: " .. buffer(start+22,16):string())


	-- Framing layer
	offset = 38
	local framing_layer = ProtoField.uint8("acn.framing", "sacn_framinglayer")
	framingtree = subtree:add(framing_layer, buffer(38, packetsize - offset), "Acn Framing Layer", packetsize - offset)
	
	flength = buffer(offset, 2):uint()
	flags = bit.rshift(flength, 12)
	length = bit.band(flength, 0x0fff)
	framingtree:add(buffer(offset, 2), "Flags: " .. flags)
	framingtree:add(buffer(offset, 2), "Length: " .. length)
	offset = offset + 2

	size = 4
	framingtree:add(buffer(offset, size), "Layer Vector: " .. buffer(offset, size):uint())
	offset = offset + size

	size = 64
	framingtree:add(buffer(offset, size), "Source Name: " .. buffer(offset, size):string())
	offset = offset + size

	size = 1
	framingtree:add(buffer(offset, size), "Priority: " .. buffer(offset, size):uint())
	offset = offset + size

	size = 2
	framingtree:add(buffer(offset, size), "Reserved")
	offset = offset + size

	size = 1
	framingtree:add(buffer(offset, size), "Sequence: " .. buffer(offset, size):uint())
	offset = offset + size

	size = 1
	framingtree:add(buffer(offset, size), "Options: " .. buffer(offset, size):uint())
	offset = offset + size

	size = 2
	framingtree:add(buffer(offset, size), "Universe: " .. buffer(offset, size):uint())
	offset = offset + size

	-- Device Management protocol
	offset = 38 + 77
	local dmp_layer = ProtoField.uint8("acn.dmp", "sacn_dmp")
	dmptree = subtree:add(dmp_layer, buffer(offset, packetsize - offset), "Device Management", packetsize - offset)

	flength = buffer(offset, 2):uint()
	flags = bit.rshift(flength, 12)
	length = bit.band(flength, 0x0fff)
	dmptree:add(buffer(offset, 2), "Flags: " .. flags)
	dmptree:add(buffer(offset, 2), "Length: " .. length)
	offset = offset + 2

	size = 1
	framingtree:add(buffer(offset, size), "Layer Vector: " .. buffer(offset, size):uint())
	offset = offset + size

	size = 1
	dmptree:add(buffer(offset, size), "Type: " .. buffer(offset, size):uint())
	offset = offset + size

	size = 2
	dmptree:add(buffer(offset, size), "First Address: " .. buffer(offset, size):uint())
	offset = offset + size

	size = 2
	dmptree:add(buffer(offset, size), "Address Increment: " .. buffer(offset, size):uint())
	offset = offset + size

	size = 2
	dmptree:add(buffer(offset, size), "Property Values: " .. buffer(offset, size):uint())
	offset = offset + size

	size = 1
	dmptree:add(buffer(offset, size), "DMX Startcode: " .. buffer(offset, size):uint())
	offset = offset + size

	str = ""
	for row = 0,32 do
		for column = 0,16 do
		  index = row * 16 + column
		  str = str .. string.format("%02x ", buffer(index, 1):uint())
		end
		str = str .. "\n"
	end
	dmptree:add(buffer(offset, 512), "Values: " .. str, buffer(offset, 512))
    
	


end -- function sacn_proto.dissector

-- sACN uses this port for multicasts
udp_table:add(5568, sacn_proto)