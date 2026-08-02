local M = {}
local LAYER_NAMES = {"identity","structure","semantics","entropy_profile","ml","runtime","memory","memory_differential"}

function M.new(target_path)
    return {
        _meta = { target=target_path or "unknown", created=os.time(), analyzer_version="2.0",
                  layers_completed={}, layer_timings={}, layer_sources={} },
        identity=nil, structure=nil, semantics=nil, entropy_profile=nil, ml=nil, runtime=nil, memory=nil, memory_differential=nil, convergence=nil,
    }
end

local function set_layer(e, name, data, source, elapsed_ms)
    e[name] = data; e._meta.layers_completed[name] = true
    if elapsed_ms then e._meta.layer_timings[name] = elapsed_ms end
    if source then e._meta.layer_sources[name] = source end
end

function M.set_identity(e, d, s, ms) set_layer(e, "identity", d, s or "moabi-features", ms) end
function M.set_structure(e, d, s, ms) set_layer(e, "structure", d, s or "moabi-ffi2", ms) end
function M.set_semantics(e, d, s, ms) set_layer(e, "semantics", d, s or "moabi-ffi2", ms) end
function M.set_entropy_profile(e, d, s, ms) set_layer(e, "entropy_profile", d, s or "moabi-features", ms) end
function M.set_ml(e, d, s, ms) set_layer(e, "ml", d, s or "moabi-ml", ms) end
function M.set_runtime(e, d, s, ms) set_layer(e, "runtime", d, s or "strace", ms) end
function M.set_memory(e, d, s, ms) set_layer(e, "memory", d, s or "moabi-memory", ms) end
function M.set_memory_differential(e, d, s, ms) set_layer(e, "memory_differential", d, s or "moabi-memory", ms) end

function M.converge(e)
    local risk_score, novelty_score, novelty_ratio = 0, 0, 0
    local signals = {}
    local st, sem, ml, rt, ep, mm, md = e.structure, e.semantics, e.ml, e.runtime, e.entropy_profile, e.memory, e.memory_differential

    local function risk_sig(txt, w) w=w or 1; risk_score=risk_score+w; signals[#signals+1]=txt end

    local expects_net = false
    if sem and sem.libraries then expects_net = sem.libraries.libcurl or sem.libraries.libssl or sem.libraries.libcrypto or false end
    e._meta._expects_network = expects_net; e._meta._expects_plain = not expects_net

    if st and st.is_elf == false then risk_sig("non-ELF object", 2) end

    if ml and ml.anomaly then
        local avg = tonumber(ml.avg_dist) or 0; local thr = tonumber(ml.threshold) or 1
        novelty_ratio = thr > 0 and avg / thr or 0; e._meta.ml_novelty_ratio = novelty_ratio
        if novelty_ratio >= 3 then novelty_score = novelty_score + 3
        elseif novelty_ratio >= 1.5 then novelty_score = novelty_score + 2
        elseif novelty_ratio > 1 then novelty_score = novelty_score + 1 end

        local cor, reasons = 0, {}
        if st and st.is_elf == false then cor=cor+1; reasons[#reasons+1]="non-ELF" end
        if ep and ep.global and ep.global > 7.5 then cor=cor+1; reasons[#reasons+1]="extreme entropy" end
        if rt and rt.attempted ~= false then
            if rt.exec_count == 1 and rt.total and rt.total < 10 then cor=cor+1; reasons[#reasons+1]="stub-like execution" end
            if e._meta._expects_plain and rt.net_ratio and rt.net_ratio > 0.1 then cor=cor+1; reasons[#reasons+1]="unexpected network" end
        end
        if cor >= 2 then risk_sig("ML novelty corroborated by "..cor.." signals ("..table.concat(reasons,", ")..")", 3)
        elseif cor == 1 then risk_sig("ML novelty weakly corroborated ("..reasons[1]..")", 1)
        elseif novelty_ratio > 1 then signals[#signals+1] = string.format("ML novelty uncorroborated (%.2fx threshold) — informational only", novelty_ratio) end
    end

    if mm and mm.profiled then
        if mm.rwx_suspicious then risk_sig("RWX executable memory region present", 2) end
        if mm.anon_exec_suspicious then risk_sig("anonymous executable memory (runtime codegen)", 2) end
    end

    if md and md.profiled then
        if md.unpack_detected then risk_sig("post-unpack execution proven (disk vs memory entropy divergence)", 4)
        elseif md.max_entropy_drop and md.max_entropy_drop > 1.5 then risk_sig("significant entropy divergence between disk and memory", 2) end
    end

    if ml and ml.exact_match then signals[#signals+1] = "exact training identity (known sample)" end

    local risk_tier = risk_score <= 0 and "CLEAR" or (risk_score <= 2 and "NOTABLE" or (risk_score <= 4 and "SUSPICIOUS" or "HOSTILE"))
    local novelty_tier = novelty_score <= 0 and "NORMAL" or (novelty_score <= 2 and "ELEVATED" or "EXTREME")

    e.convergence = { risk_score=risk_score, risk_tier=risk_tier, novelty_score=novelty_score, novelty_tier=novelty_tier, novelty_ratio=novelty_ratio, signals=signals, score=risk_score, verdict=risk_tier }
    return e.convergence
end

function M.verdict_text(e)
    if not e.convergence then M.converge(e) end
    local c = e.convergence
    local lines = { string.format("Risk:    %s (score %d)", c.risk_tier, c.risk_score), string.format("Novelty: %s (score %d, ratio %.2fx)", c.novelty_tier, c.novelty_score, c.novelty_ratio or 0) }
    if #c.signals > 0 then lines[#lines+1] = "Signals:"; for _, s in ipairs(c.signals) do lines[#lines+1] = "  - " .. s end else lines[#lines+1] = "Signals: none" end
    return table.concat(lines, "\n")
end

function M.print_report(e)
    if not e.convergence then M.converge(e) end
    local line, thin = string.rep("=", 64), string.rep("-", 64)
    print(line); print("  MOABI EVIDENCE — CONVERGENT REFLECTION"); print(line); print()
    if e.identity then print("  [IDENTITY]"); print("    Path:       " .. tostring(e.identity.path or e._meta.target)); print("    Size:       " .. tostring(e.identity.size or "?") .. " bytes"); if e.identity.sha256 then print("    SHA-256:    " .. e.identity.sha256) end; print("    Executable: " .. tostring(e.identity.executable)); print() end
    if e.structure then print("  [STRUCTURE]"); print("    ELF:        " .. tostring(e.structure.is_elf)); if e.structure.is_elf then print("    Class:      " .. tostring(e.structure.elf_class or "?")); print("    Type:       " .. tostring(e.structure.elf_type or "?")); print("    Sections:   " .. tostring(e.structure.section_count or 0)); print("    Imports:    " .. tostring(e.structure.import_count or 0)); print("    Exports:    " .. tostring(e.structure.export_count or 0)); print("    Debug:      " .. tostring(e.structure.has_debug or false)) end; print() end
    if e.semantics then print("  [SEMANTICS]"); if e.semantics.libraries then local libs={}; for k,v in pairs(e.semantics.libraries) do if v then libs[#libs+1]=k end end; table.sort(libs); print("    Libraries:  " .. (#libs>0 and table.concat(libs, ", ") or "none")) end; print() end
    if e.ml then print("  [ML VERDICT]"); print("    Class:      " .. tostring(e.ml.class or "?")); print("    Confidence: " .. tostring(e.ml.confidence or 0) .. "%"); print("    Anomaly:    " .. tostring(e.ml.anomaly or false)); print() end
    if e.runtime then print("  [RUNTIME]"); local r=e.runtime; if r.attempted == false then print("    " .. tostring(r.reason or "not attempted")); elseif r.total then print(string.format("    Syscalls:   %d total, %d unique", r.total, r.unique or 0)); print(string.format("    Entropy:    %.4f", r.entropy or 0)); print(string.format("    Network:    %d (%.1f%%)", r.net_count or 0, (r.net_ratio or 0)*100)); print(string.format("    File I/O:   %d (%.1f%%)", r.file_count or 0, (r.file_ratio or 0)*100)); print(string.format("    execve:     %d", r.exec_count or 0)) end; print() end
    if e.memory then print("  [MEMORY]"); local m=e.memory; if not m.profiled then print("    not profiled (" .. tostring(m.reason or "unknown") .. ")") else print("    Regions:    " .. tostring(m.regions_total or 0) .. " (exec " .. tostring(m.exec_regions or 0) .. ")"); print("    RWX:        " .. tostring(m.rwx_regions or 0) .. (m.rwx_suspicious and "  [!]" or "")); print("    Anon-exec:  " .. tostring(m.anon_exec_regions or 0) .. (m.anon_exec_suspicious and "  [!]" or "")); print(string.format("    Max exec H: %.4f", m.max_exec_entropy or 0)); if m.unpack_detected then print("    ** UNPACKING DETECTED (Disk vs Live Entropy Divergence) **") end end; print() end
    if e.memory_differential then print("  [MEMORY DIFFERENTIAL]"); local md=e.memory_differential; if md.profiled then print("    Available:      true"); print("    Match ratio:    " .. string.format("%.4f", md.match_ratio or 0)); print("    Max |delta H|:  " .. string.format("%.4f", md.max_entropy_drop or 0)); if md.unpack_detected then print("    ** UNPACKING DETECTED **") end else print("    " .. tostring(md.reason or "not available")) end; print() end
    print(thin); print("  [CONVERGENCE]"); print("    " .. M.verdict_text(e)); print()
    print("  [TIMING]"); local total=0; for _, name in ipairs(LAYER_NAMES) do local t=e._meta.layer_timings[name]; if t then print(string.format("    %-18s %8.2f ms", name, t)); total=total+t end end; print(string.format("    %-18s %8.2f ms", "TOTAL", total)); print()
    M.print_introspection(e); print(); print(line)
end

function M.introspect(e)
    local r = { layers={}, total_ms=0, layers_completed=0, evidence_streams=0, agreement=0 }; r.target=e._meta.target
    for _, name in ipairs(LAYER_NAMES) do local c=e._meta.layers_completed[name] or false; local src=e._meta.layer_sources[name] or "none"; local tm=e._meta.layer_timings[name]; r.layers[name]={completed=c, source=src, elapsed_ms=tm}; if tm then r.total_ms=r.total_ms+tm end; if c then r.layers_completed=r.layers_completed+1 end end
    if e.structure and e.structure.is_elf then r.agreement=r.agreement+1; r.evidence_streams=r.evidence_streams+1 end
    if e.ml then r.evidence_streams=r.evidence_streams+1; if not e.ml.anomaly then r.agreement=r.agreement+1 end end
    if e.runtime and e.runtime.attempted ~= false then r.evidence_streams=r.evidence_streams+1 end
    return r
end

function M.print_introspection(e)
    local r=M.introspect(e); print("  [INTROSPECTION]"); print(string.format("    Target:           %s", r.target or "?")); print(string.format("    Completeness:     %d/%d layers (%.0f%%)", r.layers_completed, #LAYER_NAMES, r.layers_completed/#LAYER_NAMES*100)); print(string.format("    Total time:       %.2f ms", r.total_ms)); print(); print("    Layer detail:")
    for _, name in ipairs(LAYER_NAMES) do local l=r.layers[name]; local status=l.completed and "ok" or "MISSING"; local timing=l.elapsed_ms and string.format("%.2f ms", l.elapsed_ms) or "n/a"; print(string.format("      %-18s %-7s  %s  [%s]", name, status, timing, l.source)) end
    if e.convergence then print(); print(string.format("    Self-assessed: risk=%s novelty=%s (%d signals)", e.convergence.risk_tier, e.convergence.novelty_tier, #e.convergence.signals)) end
end

local function jval(v)
    local t=type(v)
    if t=="nil" then return "null" elseif t=="boolean" then return v and "true" or "false" elseif t=="number" then if v~=v or v==math.huge or v==-math.huge then return "null" end; return string.format("%.10g", v) elseif t=="string" then return string.format("%q", v) elseif t=="table" then
        local is_arr=#v>0; if is_arr then for k,_ in pairs(v) do if type(k)~="number" then is_arr=false; break end end end
        local parts={}
        if is_arr then for i=1,#v do parts[#parts+1]=jval(v[i]) end; return "["..table.concat(parts,",").."]" else local keys={}; for k in pairs(v) do keys[#keys+1]=k end; table.sort(keys, function(a,b) return tostring(a)<tostring(b) end); for _,k in ipairs(keys) do parts[#parts+1]=string.format("%q:%s", tostring(k), jval(v[k])) end; return "{"..table.concat(parts,",").."}" end
    end; return "null"
end

function M.to_json(e) return jval({identity=e.identity, structure=e.structure, semantics=e.semantics, entropy_profile=e.entropy_profile, ml=e.ml, runtime=e.runtime, memory=e.memory, memory_differential=e.memory_differential, convergence=e.convergence}) end
function M.write_json(e, path) local f=io.open(path, "w"); if not f then return nil end; f:write(M.to_json(e)); f:write("\n"); f:close(); return true end

return M
