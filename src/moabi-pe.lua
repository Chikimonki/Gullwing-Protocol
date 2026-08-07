#!/usr/bin/env luajit
-- MOABI-PE v0.8  (LuaJIT-safe, no bitwise ops, no global "pe")
local M = {}
local LOG2 = math.log(2)

local SUSPICIOUS = {
  VirtualAlloc="high", VirtualAllocEx="high", VirtualProtect="high",
  WriteProcessMemory="critical", CreateRemoteThread="critical",
  URLDownloadToFile="high", WinExec="medium", CreateProcess="medium",
  ShellExecute="medium", LoadLibrary="medium", GetProcAddress="low",
  IsDebuggerPresent="medium", InternetOpen="medium", WSAStartup="low",
}
local MACHINE = {[0x014c]="i386",[0x8664]="x86_64",[0x01c0]="arm",[0xaa64]="arm64"}
local SUBSYS  = {[1]="native",[2]="windows_gui",[3]="windows_cui",[10]="efi_application"}

local function u16(d,o) return (d:byte(o+1) or 0) + (d:byte(o+2) or 0)*256 end
local function u32(d,o)
  return (d:byte(o+1) or 0) + (d:byte(o+2) or 0)*256
       + (d:byte(o+3) or 0)*65536 + (d:byte(o+4) or 0)*16777216
end
local function u64(d,o) return u32(d,o) + u32(d,o+4)*4294967296.0 end
local function flag(v,f) return math.floor(v/f)%2==1 end
local function cstr(d,o)
  if not o or o<0 or o>=#d then return "" end
  local s=o+1; local e=d:find("\0",s,true)
  return e and d:sub(s,e-1) or d:sub(s)
end
local function entropy(data)
  if not data or #data==0 then return 0 end
  local h={}; for i=0,255 do h[i]=0 end
  for i=1,#data do local b=data:byte(i); h[b]=h[b]+1 end
  local e=0
  for i=0,255 do if h[i]>0 then local p=h[i]/#data; e=e-p*(math.log(p)/LOG2) end end
  return e
end
local function rva_off(secs,rva)
  if not rva or rva==0 then return nil end
  for _,s in ipairs(secs) do
    local span=math.max(s.virtual_size or 0, s.raw_size or 0)
    if rva>=s.virtual_address and rva<s.virtual_address+span then
      return s.raw_offset + (rva - s.virtual_address)
    end
  end
  return nil
end

local function parse(data)
  if #data<64 then return nil,"too small" end
  if data:byte(1)~=0x4d or data:byte(2)~=0x5a then return nil,"no MZ" end
  local peoff=u32(data,0x3C)
  if peoff+24>#data then return nil,"bad PE offset" end
  if data:sub(peoff+1,peoff+4)~="PE\0\0" then return nil,"no PE sig" end

  local machine=u16(data,peoff+4)
  local nsec=u16(data,peoff+6)
  local optsz=u16(data,peoff+20)
  local opt=peoff+24
  local magic=u16(data,opt)
  local plus=(magic==0x20b)
  local subsystem=u16(data,opt+68)

  local secs={}
  local sh0=opt+optsz
  for i=0,nsec-1 do
    local sh=sh0+i*40
    if sh+40>#data then break end
    local name=data:sub(sh+1,sh+8):match("([^%z]+)") or ""
    local vsz=u32(data,sh+8)
    local va=u32(data,sh+12)
    local rsz=u32(data,sh+16)
    local roff=u32(data,sh+20)
    local chr=u32(data,sh+36)
    local blob=""
    if roff>0 and roff<#data then
      local stop=math.min(#data, roff+math.min(rsz,1048576))
      blob=data:sub(roff+1,stop)
    end
    secs[#secs+1]={
      name=name, virtual_size=vsz, virtual_address=va,
      raw_size=rsz, raw_offset=roff, entropy=entropy(blob),
      executable=flag(chr,0x20000000), readable=flag(chr,0x40000000), writable=flag(chr,0x80000000),
    }
  end

  -- PE32 import DD at opt+104; PE32+ at opt+120
  local dd = plus and (opt+120) or (opt+104)
  local irva, isz = u32(data,dd), u32(data,dd+4)
  local imports, dlls, sus = {}, {}, {}

  if irva>0 and isz>0 then
    local desc=rva_off(secs,irva)
    if desc and desc>=0 and desc<#data then
      while desc+20 <= #data do
        local oft=u32(data,desc)
        local nrva=u32(data,desc+12)
        local ft=u32(data,desc+16)
        if oft==0 and nrva==0 and ft==0 then break end
        local dll=cstr(data, rva_off(secs,nrva)):lower()
        if dll~="" then
          dlls[#dlls+1]=dll
          local trva = (oft~=0) and oft or ft
          local toff=rva_off(secs,trva)
          local width = plus and 8 or 4
          if toff then
            local cur=toff
            while cur+width <= #data do
              local entry = plus and u64(data,cur) or u32(data,cur)
              if entry==0 then break end
              local ordinal = plus and (entry>=9223372036854775808.0) or (entry>=2147483648)
              if not ordinal then
                local hn=rva_off(secs,entry)
                if hn then
                  local fn=cstr(data, hn+2)
                  if fn~="" then
                    imports[#imports+1]={dll=dll,name=fn}
                    local sev=SUSPICIOUS[fn]
                    if sev then sus[#sus+1]={dll=dll,api=fn,severity=sev} end
                  end
                end
              end
              cur=cur+width
            end
          end
        end
        desc=desc+20
      end
    end
  end

  local high={}
  for _,s in ipairs(secs) do
    if s.entropy>=7.0 then high[#high+1]={name=s.name,entropy=s.entropy} end
  end

  return {
    machine=MACHINE[machine] or string.format("0x%04x",machine),
    subsystem=SUBSYS[subsystem] or string.format("0x%04x",subsystem),
    pe32plus=plus,
    sections=secs,
    imports=imports,
    dll_list=dlls,
    suspicious_imports=sus,
    high_entropy_sections=high,
    overall_entropy=entropy(data),
    size=#data,
  }
end

function M.analyze(path)
  local f=io.open(path,"rb"); if not f then return nil,"cannot open" end
  local data=f:read("*a"); f:close()
  local r,err=parse(data); if not r then return nil,err end
  r.path=path
  return r
end

function M.evidence_fragment(r)
  if not r then return {profiled=false} end
  local sus={}
  for _,s in ipairs(r.suspicious_imports or {}) do
    sus[#sus+1]=string.format("%s!%s [%s]",s.dll,s.api,s.severity)
  end
  return {
    profiled=true, format="PE",
    machine=r.machine, subsystem=r.subsystem,
    sections=#(r.sections or {}), imports_count=#(r.imports or {}),
    dlls=r.dll_list or {}, suspicious_imports=sus,
    overall_entropy=r.overall_entropy or 0,
    high_entropy_sections=r.high_entropy_sections or {},
    size=r.size or 0,
  }
end

function M.print_report(r)
  if not r then print("PE analysis failed"); return end
  print("============================================================")
  print("  MOABI PE ANALYSIS v0.8")
  print("============================================================")
  print("  File:       "..tostring(r.path or "unknown"))
  print("  Machine:    "..tostring(r.machine))
  print("  Subsystem:  "..tostring(r.subsystem))
  print(string.format("  Sections:   %d", #(r.sections or {})))
  print(string.format("  Imports:    %d functions from %d DLLs", #(r.imports or {}), #(r.dll_list or {})))
  print(string.format("  Entropy:    %.4f / 8.0", r.overall_entropy or 0))
  if r.dll_list and #r.dll_list>0 then
    print("  DLLs:")
    for i,d in ipairs(r.dll_list) do
      if i<=25 then print("    "..d) end
    end
    if #r.dll_list>25 then print(string.format("    ... +%d more", #r.dll_list-25)) end
  end
  if r.suspicious_imports and #r.suspicious_imports>0 then
    print("  Suspicious imports:")
    for _,s in ipairs(r.suspicious_imports) do
      print(string.format("    %s!%s [%s]", s.dll, s.api, s.severity))
    end
  end
  print("============================================================")
end

-- CLI only when executed directly, never on require()
local prog = tostring(arg and arg[0] or "")
if prog:match("moabi%-pe%.lua$") and arg[1] then
  local result, err = M.analyze(arg[1])
  if not result then
    io.stderr:write("ERROR: "..tostring(err).."\n")
    os.exit(1)
  end
  M.print_report(result)
end

return M
