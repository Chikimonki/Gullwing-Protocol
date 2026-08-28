# Gullwing Protocol — Resource Requirements

## CPU Usage

| Operation | CPU Impact | Duration | Notes |
|-----------|-----------|----------|-------|
| Static analysis (25ms) | Minimal | 25ms | Single core, negligible |
| Deep analysis (--deep-memory) | Moderate | 3.4s | Uses strace + /proc scanning |
| Watch mode (single directory) | Low | Continuous | Polls every 5s default |
| Watch mode (entire filesystem `/`) | High | Continuous | Scans every file — NOT recommended |
| wsolver (basic) | High | Minutes | CPU-bound symbolic execution |
| wsolver (Docker/KLEE) | Very High | Hours | Full symbolic execution |
| LLM analysis (Ollama) | Moderate | Seconds | Depends on model size |

## Memory Usage

| Component | RAM Usage | Notes |
|-----------|-----------|-------|
| Gullwing core | ~50MB | LuaJIT footprint |
| Watch mode | ~10MB per directory | Minimal overhead |
| Ollama (phi4-mini) | ~2.5GB | Model loaded in RAM |
| Ollama (qwen3.5:9b) | ~6.6GB | Larger model |
| wsolver (basic) | ~100MB | Native tools |
| wsolver (Docker) | ~2-4GB | KLEE + solvers |
| Cormorant Bus (Elixir) | ~100MB | Fleet communication |

## Disk Usage

| Component | Disk Space | Notes |
|-----------|-----------|-------|
| Gullwing core | ~50MB | Source + binaries |
| Quarantine copies | Same as binary | Forensic copies preserved |
| Reports | ~2KB per scan | JSON evidence files |
| wsolver Docker image | ~5GB | One-time build |
| Ollama models | 2.5-6.6GB each | Optional |
| Training data | ~100MB | ML model + samples |

## Watch Mode Resource Guide

### Light Watch (Recommended)
```bash
gullwing watch ~/Downloads
gullwing watch /usr/bin
gullwing watch /tmp
```
**CPU:** ~1-2% per directory
**RAM:** ~30MB total
**Safe for:** Any machine

### Medium Watch
```bash
gullwing watch ~/
gullwing watch /usr/
gullwing watch /opt/
```
**CPU:** ~5-10%
**RAM:** ~100MB
**Safe for:** Desktops, servers

### Heavy Watch (NOT Recommended for `/`)
```bash
gullwing watch /
```
**CPU:** 20-50% (constant)
**RAM:** 500MB+
**Disk I/O:** High (constantly reading)
**Safe for:** Only dedicated security appliances

**Why `/` is problematic:**
- `/proc` changes constantly (process info)
- `/sys` changes constantly (kernel state)
- `/dev` changes constantly (device files)
- `/tmp` has frequent churn
- Every log write triggers a scan

**Better approach for full coverage:**
```bash
gullwing watch /home
gullwing watch /usr/bin
gullwing watch /usr/local/bin
gullwing watch /opt
gullwing watch /var/www
gullwing watch /tmp
```

## Enterprise Scale Estimates

| Nodes | CPU (total) | RAM (total) | Network | Notes |
|-------|-------------|-------------|---------|-------|
| 1-10 | Minimal | 1-5GB | Low | Single admin manageable |
| 10-50 | Low | 5-20GB | Moderate | Fleet bus recommended |
| 50-100 | Moderate | 20-50GB | High | Headscale required |
| 100+ | High | 50GB+ | Very High | Enterprise deployment |

## Optimization Tips

1. **Use static-only for routine scans** (25ms, minimal resources)
2. **Schedule deep scans** (nightly, not continuous)
3. **Watch specific directories** (not `/`)
4. **Use phi4-mini for LLM** (2.5GB vs 6.6GB)
5. **Run wsolver on-demand** (not continuously)
6. **Configure watch intervals** (5s default, can increase to 30s)

## Bottom Line

**For a typical workstation:**
- CPU: 1-5% (light watch mode)
- RAM: 50-100MB (core + light watch)
- Disk: 50MB (core) + quarantine copies

**For a security server:**
- CPU: 10-20% (medium watch + occasional deep scans)
- RAM: 1-2GB (core + watch + occasional LLM)
- Disk: 50MB core + ~5GB if using Docker

**Gullwing is lightweight by design.** The heavy lifting (wsolver Docker, large LLM models) is optional and on-demand.
