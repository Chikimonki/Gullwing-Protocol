#!/usr/bin/env luajit

local SRC = "/mnt/d/moabi/src"
package.path = SRC .. "/?.lua;" .. package.path

local ev = require("moabi-evidence")
local MF = require("moabi-features")
local mem = require("moabi-memory")
local pe_mod = require("moabi-pe")
local clock = require("moabi-clock")

local LOG2 = math.log(2)
local EPSILON = 1e-10

local function now_ms()
    return clock.now_ms()
end

local DEFAULT_MODEL = "/mnt/d/moabi/reports/system.model"
local function shq(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end
local function file_exists(p) local f=io.open(p,"rb"); if f then f:close(); return true end; return false end
local function is_executable(p)
    local h=io.popen("test -x "..shq(p).." && echo 1"); if not h then return false end
    local r=h:read("*l"); h:close(); return r=="1"
end

local function sense_all_static(target)
    local t0=now_ms(); local r,err=MF.extract(target)
    if not r then error("Extraction failed: "..(err or "unknown")) end
    local sha="unknown"; local h=io.popen("sha256sum "..shq(target).." 2>/dev/null")
    if h then sha=(h:read("*l") or ""):match("^(%x+)"); h:close() end
    local identity={path=target,size=r.size,sha256=sha,executable=is_executable(target)}
    local entropy_profile={global=r.feat.entropy,byte_mean=r.feat.byte_mean,byte_stddev=r.feat.byte_stddev,null_ratio=r.feat.null_ratio,printable_ratio=r.feat.printable_ratio,available=true}
    local st={is_elf=(r.feat.is_elf~=nil) and (tonumber(r.feat.is_elf)==1)}
    if st.is_elf then
        st.elf_class=(r.feat.elf_class_num==2) and "ELF64" or "ELF32"
        local t=r.feat.elf_type_num; st.elf_type=({[0]="NONE",[1]="REL",[2]="EXEC",[3]="DYN",[4]="CORE"})[t] or tostring(t)
        st.section_count=r.feat.section_count or 0; st.import_count=r.feat.import_count or 0; st.export_count=r.feat.export_count or 0; st.has_debug=r.feat.has_debug==1
    end
    local sem={libraries={libssl=r.feat.has_libssl==1,libcrypto=r.feat.has_libcrypto==1,libcurl=r.feat.has_libcurl==1,libz=r.feat.has_libz==1,lzma=r.feat.has_lzma==1,ncurses=r.feat.has_ncurses==1,readline=r.feat.has_readline==1,python=r.feat.has_libpython==1,perl=r.feat.has_libperl==1,ruby=r.feat.has_libruby==1},symbols=r.symbols or {},strings=r.toolchain or {}}
    return {identity=identity,entropy_profile=entropy_profile,structure=st,semantics=sem,vec=r.vec,source=r.source or "moabi-features",timings={identity=now_ms()-t0,structure=0,semantics=0,entropy_profile=0},elapsed=now_ms()-t0}
end

local function sense_ml(model_path,vec)
    local t0=now_ms(); local chunk,err=loadfile(model_path)
    if not chunk then return {available=false,error=err},now_ms()-t0 end
    local ok,model=pcall(chunk)
    if not ok or type(model)~="table" or not model.samples then return {available=false,error="invalid model"},now_ms()-t0 end
    local n=MF.N; local mean=model.normalization.mean or {}; local std=model.normalization.std or {}
    local function norm(v) local o={}; for i=1,n do local m=mean[i]or 0; local s=std[i]or 1; if math.abs(s)<1e-10 then s=1 end; o[i]=(v[i]-m)/s end; return o end
    local nv=norm(vec); local nbs={}
    for _,s in ipairs(model.samples) do local sv=norm(s.vec); local d=0; for i=1,n do local x=nv[i]-sv[i]; d=d+x*x end; nbs[#nbs+1]={dist=math.sqrt(d),label=s.label,filename=s.filename or "?"} end
    table.sort(nbs,function(a,b) return a.dist<b.dist end)
    local k=math.min(model.k or 5,#nbs); local scores,tw,sd={},0.0,0.0; local cc=model.class_counts or (model.info and model.info.class_counts) or {}
    for i=1,k do local lbl=nbs[i].label; local sz=cc[lbl]or 1; local w=1/(nbs[i].dist+1e-10); scores[lbl]=(scores[lbl]or 0)+w; tw=tw+w; sd=sd+nbs[i].dist end
    local best,bests="unknown",-1; for lbl,sc in pairs(scores) do if sc>bests then best,bests=lbl,sc end end
    local avg=sd/k; local thr=model.anomaly_threshold or (model.info and model.info.anomaly_threshold) or 7.66
    return {available=true,class=best,confidence=tw>0 and (bests/tw)*100 or 0,anomaly=avg>thr,exact_match=nbs[1] and nbs[1].dist<=1e-10,avg_dist=avg,threshold=thr,model_version=model.info and model.info.version or 3},now_ms()-t0
end

local NET={socket=1,connect=1,accept=1,accept4=1,bind=1,listen=1,sendto=1,recvfrom=1,sendmsg=1,recvmsg=1}
local FIL={open=1,openat=1,openat2=1,read=1,write=1,close=1,stat=1,fstat=1,lstat=1,newfstatat=1,access=1}
local function sense_runtime(target,static_only)
    local t0=now_ms()
    if static_only then return {attempted=false,reason="skipped (--static-only)"},now_ms()-t0 end
    if not is_executable(target) then return {attempted=false,reason="not executable"},now_ms()-t0 end
    local trace=os.tmpname()..".moabi"; os.execute("timeout 3s strace -f -qq -o "..shq(trace).." -- "..shq(target).." >/dev/null 2>&1")
    local f=io.open(trace,"r"); if not f then os.remove(trace); return {attempted=false,reason="trace unavailable"},now_ms()-t0 end
    local counts,total={},0; for line in f:lines() do local sc=line:match("^%s*%d+%s+([%a_][%w_]*)%(") or line:match("^%s*([%a_][%w_]*)%("); if sc then counts[sc]=(counts[sc]or 0)+1; total=total+1 end end
    f:close(); os.remove(trace)
    local net,fil,uniq=0,0,0; for sc,n in pairs(counts) do uniq=uniq+1; if NET[sc] then net=net+n end; if FIL[sc] then fil=fil+n end end
    local e=0; if total>0 then for _,n in pairs(counts) do local p=n/total; e=e-p*(math.log(p)/LOG2) end end
    return {attempted=true,total=total,unique=uniq,entropy=e,net_count=net,file_count=fil,exec_count=counts.execve or 0,net_ratio=total>0 and net/total or 0,file_ratio=total>0 and fil/total or 0},now_ms()-t0
end

local function main()
    local target=arg[1]
    if not target then print("Usage: luajit moabi-reflect.lua <target> [--model p] [--static-only] [--json] [--deep-memory]"); return 0 end
    if not file_exists(target) then io.stderr:write("Target not found: "..target.."\n"); return 1 end
    local model,static_only,json_out,deep_memory=DEFAULT_MODEL,false,false,false
    local i=2; while i<=#arg do
        if arg[i]=="--static-only" then static_only=true
        elseif arg[i]=="--json" then json_out=true
        elseif arg[i]=="--deep-memory" then deep_memory=true
        elseif arg[i]=="--model" and arg[i+1] then model=arg[i+1]; i=i+1 end
        i=i+1
    end

    local f=io.open(target,"rb"); if not f then io.stderr:write("Cannot open target\n"); return 1 end
    local magic=f:read(2) or ""; f:close()
    local e=ev.new(target)

    if magic=="MZ" then
        local t0=now_ms(); local pe,err=pe_mod.analyze(target)
        if not pe then io.stderr:write("PE analysis failed: "..tostring(err).."\n"); return 1 end
        ev.set_identity(e,{path=target,size=pe.size,sha256=tostring(pe.overall_entropy),executable=true},"moabi-pe",now_ms()-t0)
        ev.set_entropy_profile(e,{global=pe.overall_entropy,available=true},"moabi-pe",0)
        ev.set_structure(e,{is_pe=true,machine=pe.machine,subsystem=pe.subsystem,sections=#pe.sections},"moabi-pe",0)
        ev.set_semantics(e,{dlls=pe.dll_list,suspicious_imports=pe.suspicious_imports},"moabi-pe",0)
    else
        local static=sense_all_static(target)
        if not static then io.stderr:write("Static extraction failed\n"); return 1 end
        ev.set_identity(e,static.identity,"moabi-features",static.elapsed)
        ev.set_entropy_profile(e,static.entropy_profile,"moabi-features",0)
        ev.set_structure(e,static.structure,static.source,0)
        ev.set_semantics(e,static.semantics,static.source,0)
        local ml,ml_ms=sense_ml(model,static.vec)
        ev.set_ml(e,ml,"moabi-ml/inline",ml_ms)
        local rt,rt_ms=sense_runtime(target,static_only)
        ev.set_runtime(e,rt,"strace",rt_ms)
        -- Memory inspection (supports --deep-memory)
        if not static_only then
            local mem_t0 = now_ms()
            local memres = mem.inspect(target, { deep = deep_memory })
            local frag = mem.evidence_fragment(memres)
            ev.set_memory(e, frag, "moabi-memory", now_ms() - mem_t0)
            ev.set_memory_differential(e, frag, "moabi-memory", now_ms() - mem_t0)
        else
            ev.set_memory(e, { profiled = false, reason = "skipped (--static-only)" }, "moabi-memory", 0)
            ev.set_memory_differential(e, { profiled = false, reason = "skipped (--static-only)" }, "moabi-memory", 0)
        end
    end

    -- Temporal differential analysis is standalone in v2.
    if type(ev.set_memory_differential) == "function" then
        ev.set_memory_differential(
            e,
            {
                profiled = false,
                error = "standalone analyzer: use moabi-diff.lua",
            },
            "moabi-diff",
            0
        )
    end

    ev.converge(e); ev.print_report(e)
    if json_out then local name=target:match("([^/]+)$") or "unknown"; local out="/mnt/d/moabi/reports/"..name..".evidence.json"; ev.write_json(e,out); print("JSON written: "..out) end
    return 0
end

local ok,ret=pcall(main)
if not ok then io.stderr:write("\nERROR: "..tostring(ret).."\n"); os.exit(1) end
os.exit(ret or 0)
