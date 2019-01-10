followupCNAME = true
prefix = "64:ff9b::"
prefixPTR = "b.9.f.f.4.6.0.0.ip6.arpa."
recurdomainstr = "re.example.com"
recurdomain = newDN(recurdomainstr)

function isIpAddress(ip)
  if not ip then return false end
  local a,b,c,d = ip:match("^(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)$")
  a = tonumber(a)
  b = tonumber(b)
  c = tonumber(c)
  d = tonumber(d)
  if not a or not b or not c or not d then return false end
  if a < 0 or 255 < a then return false end
  if b < 0 or 255 < b then return false end
  if c < 0 or 255 < c then return false end
  if d < 0 or 255 < d then return false end
  return true
end

function prePrefix(prefix)
  local ct = 0
  for c in prefix:gmatch(".") do
    if c == ':' then
      ct = ct + 1
    end
  end
  if ct < 8 then
    return prefix
  else
    return prefix:sub(1, -2)
  end
end

function getIP6ADDRSEC(a, b)
  return string.format("%02x", a)..string.format("%02x", b)
end

function getDNS64AAAA(prefix, ip)
  local a,b,c,d = ip:match("^(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)$")
  return prePrefix(prefix)..getIP6ADDRSEC(tonumber(a), tonumber(b))..":"..getIP6ADDRSEC(tonumber(c), tonumber(d))
end

function preresolve(dq)
  if dq.qname:isPartOf(recurdomain) then
    local name = dq.qname:toStringNoDot()
    name = name:sub(1, (name:len() - recurdomainstr:len() - 1))
    if isIpAddress(name) then
      if dq.qtype == pdns.A then
        dq:addAnswer(pdns.A, name)
      elseif dq.qtype == pdns.AAAA then
        dq:addAnswer(pdns.AAAA, getDNS64AAAA(prefix, name))
      else
        dq.appliedPolicy.policyKind = pdns.policykinds.NODATA
      end
    else
      dq:addAnswer(pdns.CNAME, name)
      if followupCNAME then
        dq.followupFunction = "followCNAMERecords"
      end
    end
    return true;
  end
  if dq.qtype == pdns.PTR and dq.qname:isPartOf(newDN(prefixPTR)) then
    dq.followupFunction = "getFakePTRRecords"
    dq.followupPrefix = prefix
    dq.followupName = dq.qname
    return true
  end
  return false
end

function nodata ( dq )
  if dq.qtype ~= pdns.AAAA then
    return false
  end  --  only AAAA records

  dq.followupFunction = "getFakeAAAARecords"
  dq.followupPrefix = prefix
  dq.followupName = dq.qname
  return true
end
