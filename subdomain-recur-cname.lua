recurdomainstr = "re.example.com"
recurdomain = newDN(recurdomainstr)

function isIpAddress(ip)
  if not ip then return false end
  local a,b,c,d=ip:match("^(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)$")
  a=tonumber(a)
  b=tonumber(b)
  c=tonumber(c)
  d=tonumber(d)
  if not a or not b or not c or not d then return false end
  if a<0 or 255<a then return false end
  if b<0 or 255<b then return false end
  if c<0 or 255<c then return false end
  if d<0 or 255<d then return false end
  return true
end

function preresolve(dq)
  if dq.qname:isPartOf(recurdomain) then
    local name = dq.qname:toStringNoDot()
    name = name:sub(1, (name:len() - recurdomainstr:len() - 1))
    if isIpAddress(name) then
      if dq.qtype == pdns.A then
        dq:addAnswer(pdns.A, name)
      else
        dq.appliedPolicy.policyKind = pdns.policykinds.NODATA
      end
    else
      dq:addAnswer(pdns.CNAME, name)
    end
    return true;
  end
  return false;
end
