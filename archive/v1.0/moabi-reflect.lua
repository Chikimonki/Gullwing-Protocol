#!/usr/bin/env luajit
local SRC = "/mnt/d/moabi/src"
package.path = SRC .. "/?.lua;" .. package.path
local ev = require("moabi-evidence")
local MF = require("moabi-features")
local mem_mod = require("moabi-memory")
local ffi = require("ffi")
ffi.cdef[[ struct moabi_timespec { long tv_sec; long tv_nsec; }; int clock_gettime(int clock_id, struct moabi_timespec *tp); ]]
local CLOCK_MONOTONIC = 1
local _ts = ffi.new("struct moabi_timespec[1]")
local function now_ms()
    if ffi.C.clock_gettime(CLOCK_MONOTONIC, _ts) == 0 then
        return tonumber(_ts[0].tv_sec)*1000 + tonumber(_ts[0].tv_nsec)/1e6
    end
    return os.clock()*1000
end
local DEFAULT_MODEL = "/mnt/d/moabi/reports/system.model"
local LOG2 = math.log(2)
local function shq(s) return "'"..tostring(s):gsub("'","'\\''").."'" end
local function file_exists(p) local f=io.open(p,"rb"); if f then f:close(); return true end; return false end
local function is_exec(p) local h=io.popen("test -x "..shq(p).." && echo 1"); if not h then return false end; local r=h:read("*l"); h:close(); return r=="1" end

local function sense_all_static(target)
    local t0 = now_ms()
    local r = MF.extract(target)
    if not r then return nil end
    local sha = nil
    local h = io.popen("sha256sum "..shq(target).." 2>/dev/null")
    if h then sha=(h:read("*l") or ""):match("^(%x+)"); h:close() end
    local identity = { path=target, size=r.size, sha256=sha, executable=is_exec(target) }
    local entropy_profile = { global=r.feat.entropy, byte_mean=r.feat.byte_mean, byte_stddev=r.feat.byte_stddev, null_ratio=r.feat.null_ratio, printable_ratio=r.feat.printable_ratio }
    local st = {}
    st.is_elf = (r.feat.is_elf ~= nil) and (r.feat.is_elf == 1.0)
    if st.is_elf then
        st.elf_class=(r.feat.elf_class_num==2) and "ELF64" or "ELF32"
        local t=r.feat.elf_type_num
        st.elf_type=({[0]="NONE",[1]="REL",[2]="EXEC",[3]="DYN",[4]="CORE"})[t] or tostring(t)
        st.section_count=r.feat.section_count; st.import_count=r.feat.import_count; st.export_count=r.feat.export_count; st.has_debug=r.feat.has_debug==1
    end
    local sem = { libraries={
        libssl=r.feat.has_libssl==1, libcrypto=r.feat.has_libcrypto==1, libcurl=r.feat.has_libcurl==1,
        libz=r.feat.has_libz==1, lzma=r.feat.has_lzma==1, ncurses=r.feat.has_ncurses==1,
        readline=r.feat.has_readline==1, python=r.feat.has_libpython==1, perl=r.feat.has_libperl==1, ruby=r.feat.has_libruby==1},
        symbols=r.symbols, strings=r.toolchain }
    return { identity=identity, entropy_profile=entropy_profile, structure=st, semantics=sem, vec=r.vec, source=r.source, elapsed=now_ms()-t0 }
end

local function sense_ml(model_path, vec)
    local t0 = now_ms()
    local chunk=loadfile(model_path)
    if not chunk then return {available=false}, now_ms()-t0 end
    local ok,model=pcall(chunk)
    if not ok or type(model)~="table" then return {available=false}, now_ms()-t0 end
    local n=MF.N
    local mean=model.normalization.mean or {}
    local std=model.normalization.std or {}
    local function norm(v) local o={}; for i=1,n do local m=mean[i] or 0; local s=std[i] or 1; if math.abs(s)<1e-10 then s=1 end; o[i]=(v[i]-m)/s end; return o end
    local nv=norm(vec)
    local nbs={}
    for _,s in ipairs(model.samples) do
        local sv=norm(s.vec); local d=0; for i=1,n do local x=nv[i]-sv[i]; d=d+x*x end
        nbs[#nbs+1]={dist=math.sqrt(d), label=s.label, filename=s.filename or "?"}
    end
    table.sort(nbs, function(a,b) return a.dist < b.dist end)
    local k=math.min(model.k or 5, #nbs)
    local scores,tw,sd={},0,0
    local cc=model.class_counts or (model.info and model.info.class_counts) or {}
    for i=1,k do local lbl=nbs[i].label; local sz=cc[lbl] or 1; local w=(1/(nbs[i].dist+1e-10))/sz; scores[lbl]=(scores[lbl] or 0)+w; tw=tw+w; sd=sd+nbs[i].dist end
    local best,bests="unknown",-1; for l,s in pairs(scores) do if s>bests then best,bests=l,s end end
    local avg=sd/k
    local thr=model.anomaly_threshold or (model.info and model.info.anomaly_threshold) or 7.5
    return {available=true, class=best, confidence=tw>0 and (bests/tw)*100 or 0, anomaly=avg>thr, exact_match=nbs[1] and nbs[1].dist<=1e-10, avg_dist=avg, threshold=thr}, now_ms()-t0
end

local function sense_runtime(target, static_only)
    local t0=now_ms()
    if static_only then return {attempted=false, reason="skipped (--static-only)"}, now_ms()-t0 end
    if not is_exec(target) then return {attempted=false, reason="not executable"}, now_ms()-t0 end
    local trace=os.tmpname()..".moabi"
    os.execute("timeout 3s strace -f -qq -o "..shq(trace).." -- "..shq(target).." >/dev/null 2>&1")
    local f=io.open(trace,"r")
    if not f then os.remove(trace); return {attempted=false, reason="trace unavailable"}, now_ms()-t0 end
    local counts,total={},0
    for line in f:lines() do local sc=line:match("^%s*%d+%s+([%a_][%w_]*)%(") or line:match("^%s*([%a_][%w_]*)%("); if sc then counts[sc]=(counts[sc] or 0)+1; total=total+1 end end
    f:close(); os.remove(trace)
    local net,fil,uniq=0,0,0
    for sc,n in pairs(counts) do uniq=uniq+1; if ({socket=1,connect=1,accept=1})[sc] then net=net+n end; if ({open=1,openat=1,read=1,write=1})[sc] then fil=fil+n end end
    local e=0; if total>0 then for _,n in pairs(counts) do local p=n/total; e=e-p*(math.log(p)/LOG2) end end
    return {attempted=true, total=total, unique=uniq, entropy=e, net_count=net, file_count=fil, exec_count=counts.execve or 0, net_ratio=total>0 and net/total or 0, file_ratio=total>0 and fil/total or 0}, now_ms()-t0
end

local function main()
    local target=arg[1]
    if not target then print("Usage: luajit moabi-reflect.lua <target> [--static-only] [--json]"); return 0 end
    local DEFAULT_MODEL="/mnt/d/moabi/reports/system.model"
    local model,static_only,json_out=DEFAULT_MODEL,false,false
    local i=2 while i<=#arg do if arg[i]=="--static-only" then static_only=true elseif arg[i]=="--json" then json_out=true elseif arg[i]=="--model" and arg[i+1] then model=arg[i+1]; i=i+1 end; i=i+1 end

    local e=ev.new(target)
    local static=sense_all_static(target)
    if not static then io.stderr:write("Extraction failed\n"); return 1 end
    ev.set_identity(e, static.identity, "moabi-features", static.elapsed)
    ev.set_entropy_profile(e, static.entropy_profile, "moabi-features", 0)
    ev.set_structure(e, static.structure, static.source, 0)
    ev.set_semantics(e, static.semantics, static.source, 0)
    local ml,ml_ms=sense_ml(model, static.vec)
    ev.set_ml(e, ml, "moabi-ml/inline", ml_ms)
    local rt,rt_ms=sense_runtime(target, static_only)
    ev.set_runtime(e, rt, "strace", rt_ms)
    if not static_only then
        local mem_t0=now_ms()
        local memres=mem_mod.inspect(target)
        ev.set_memory(e, mem_mod.evidence_fragment(memres), "moabi-memory", now_ms()-mem_t0)
    end
    ev.converge(e)
    ev.print_report(e)
    if json_out then local name=target:match("([^/]+)$") or "unknown"; local out="/mnt/d/moabi/reports/"..name..".evidence.json"; ev.write_json(e,out); print("JSON: "..out) end
    return 0
end

local ok,ret=pcall(main)
if not ok then io.stderr:write("\nERROR: "..tostring(ret).."\n"); os.exit(1) end
os.exit(ret or 0)
