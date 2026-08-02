#!/usr/bin/env luajit
local ffi2_ok, ffi2 = pcall(require, "moabi-ffi2")
local LOG2 = math.log(2)
local WINDOW = 1024
local FEATURE_NAMES = {
    "size_log","entropy","byte_mean","byte_stddev","null_ratio","printable_ratio",
    "is_elf","elf_class_num","elf_type_num","entropy_variance","high_entropy_ratio",
    "low_entropy_ratio","top_byte_ratio","ff_ratio","section_count","import_count",
    "export_count","has_libssl","has_libcrypto","has_libcurl","has_libz","has_lzma",
    "has_ncurses","has_readline","has_libpython","has_libperl","has_libruby","has_libselinux"
}
local M = { FEATURE_NAMES = FEATURE_NAMES, N = #FEATURE_NAMES }

local function entropy_hist(hist, n)
    if n <= 0 then return 0 end
    local e=0; for i=0,255 do local c=hist[i] or 0; if c>0 then local p=c/n; e=e-p*(math.log(p)/LOG2) end end; return e
end

function M.extract(path)
    local f = io.open(path, "rb")
    if not f then return nil, "open failed" end
    local data = f:read("*a"); f:close()
    if not data or #data==0 then return nil, "empty" end
    local size, hist = #data, {}
    for i=0,255 do hist[i]=0 end
    local sum,sq,nullc,ffc,printc=0,0,0,0,0
    for i=1,size do local b=data:byte(i); hist[b]=hist[b]+1; sum=sum+b; sq=sq+b*b; if b==0 then nullc=nullc+1 end; if b==255 then ffc=ffc+1 end; if b>=32 and b<=126 then printc=printc+1 end end
    local mean=sum/size
    local var=math.max(0, sq/size - mean*mean)
    local top=0; for i=0,255 do if hist[i]>top then top=hist[i] end end
    local ent=entropy_hist(hist,size)

    local feat={}
    feat.size_log=math.log(size+1); feat.entropy=ent; feat.byte_mean=mean; feat.byte_stddev=math.sqrt(var)
    feat.null_ratio=nullc/size; feat.printable_ratio=printc/size; feat.top_byte_ratio=top/size; feat.ff_ratio=ffc/size
    feat.packer_detected = (ent>7.2 and nullc/size<0.05 and printc/size<0.10) and 1 or 0

    if size>=18 and data:byte(1)==0x7f and data:byte(2)==0x45 and data:byte(3)==0x4c and data:byte(4)==0x46 then
        feat.is_elf=1.0; feat.elf_class_num=0.0+data:byte(5)
        local le=data:byte(6)==1; feat.elf_type_num= le and (data:byte(17)+data:byte(18)*256) or (data:byte(17)*256+data:byte(18))
    else feat.is_elf=0.0; feat.elf_class_num=0.0; feat.elf_type_num=0.0 end

    local nw=math.floor(size/WINDOW)
    if nw>=2 then
        local wes={}; for w=0,nw-1 do local wh={}; for i=0,255 do wh[i]=0 end; local s=w*WINDOW+1; for i=s,s+WINDOW-1 do local b=data:byte(i); wh[b]=wh[b]+1 end; wes[#wes+1]=entropy_hist(wh,WINDOW) end
        local es=0; for _,v in ipairs(wes) do es=es+v end; local em=es/#wes; local evar,hi,lo=0,0,0; for _,v in ipairs(wes) do evar=evar+(v-em)*(v-em); if v>7 then hi=hi+1 end; if v<2 then lo=lo+1 end end
        feat.entropy_variance=evar/#wes; feat.high_entropy_ratio=hi/#wes; feat.low_entropy_ratio=lo/#wes
    else feat.entropy_variance=0; feat.high_entropy_ratio=0; feat.low_entropy_ratio=0 end

    feat.section_count=0; feat.import_count=0; feat.export_count=0; feat.has_libssl=0; feat.has_libcrypto=0; feat.has_libcurl=0; feat.has_libz=0; feat.has_lzma=0; feat.has_ncurses=0; feat.has_readline=0; feat.has_libpython=0; feat.has_libperl=0; feat.has_libruby=0; feat.has_libselinux=0
    local lib_list={}

    if ffi2_ok and ffi2 then
        if type(ffi2.extract_elf_features)=="function" then local ok,r=pcall(ffi2.extract_elf_features, path); if ok and r then feat.section_count=r.section_count or 0; feat.import_count=r.import_count or r.dependency_count or 0; feat.export_count=r.export_count or 0 end end
        if type(ffi2.extract_dependency_features)=="function" then local ok,d=pcall(ffi2.extract_dependency_features, path); if ok and d then feat.has_libssl=d.has_libssl or 0; feat.has_libcrypto=d.has_libcrypto or 0; feat.has_libcurl=d.has_libcurl or 0; feat.has_libz=d.has_libz or 0; feat.has_lzma=d.has_liblzma or 0; feat.has_ncurses=d.has_ncurses or 0; feat.has_readline=d.has_readline or 0; feat.has_libpython=d.has_python or 0; feat.has_libperl=d.has_perl or 0; feat.has_libruby=d.has_ruby or 0; feat.has_libselinux=d.has_libselinux or 0; feat.import_count=math.max(feat.import_count, d.dependency_count or 0); lib_list=d.libs or {} end end
    end

    local symbols={has_py_eval=false, has_curl_easy=false, has_ssl_ctx=false}
    if data:find("PyEval_",1,true) or data:find("libpython",1,true) then symbols.has_py_eval=true; feat.has_libpython=1 end
    if data:find("curl_easy_init",1,true) then symbols.has_curl_easy=true; feat.has_libcurl=1 end
    if data:find("SSL_CTX_new",1,true) then symbols.has_ssl_ctx=true; feat.has_libssl=1 end
    local toolchain={has_gcc=data:find("GCC:",1,true)~=nil, has_zig=data:find("zig",1,true)~=nil, has_rust=data:find("rustc",1,true)~=nil}

    local vec={}; for i,name in ipairs(FEATURE_NAMES) do vec[i]=feat[name] or 0.0 end
    return { data=data, size=size, feat=feat, vec=vec, libs=lib_list, symbols=symbols, toolchain=toolchain, source="moabi-features" }
end
return M
