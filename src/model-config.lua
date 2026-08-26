-- Tiered LLM Configuration
local MODELS = {
    quick = {
        name = "phi4-mini",
        use_case = "Rapid triage, initial screening",
        timeout = 30,
    },
    deep = {
        name = "qwen3.5-9b",
        use_case = "Compliance reports, detailed analysis",
        timeout = 120,
    },
    default = "phi4-mini"  -- Keeps current behavior
}

return MODELS
