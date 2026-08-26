#!/bin/bash
export GULLWING_LLM=qwen3.5-9b
export GULLWING_LLM_DEEP=qwen3.5-9b
echo "Starting with Qwen3.5-9b..."
luajit src/moabi-serve.lua
