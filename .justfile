# Convenient command runner for common development tasks
# ============================================================================
# Configuration
# ============================================================================
# Use bash with strict error handling for all recipes

set shell := ["bash", "-euo", "pipefail", "-c"]

# Automatically load .env file if present

set dotenv-load := true

# ============================================================================
# Default Recipe
# ============================================================================

# List all available commands (default)
default:
    @just --list

# ============================================================================
# AI RECIPES
# ============================================================================

# Start Claude interactive session (args: additional claude code flags)
claude *args="":
    npx -y @anthropic-ai/claude-code {{ args }}

# ============================================================================
# NOIR / ZERO-KNOWLEDGE PROOF RECIPES
# ============================================================================

# Test Noir circuit
noir-test:
    nargo test

# Execute Noir circuit (generates witness)
noir-execute:
    nargo execute

# Generate proof using Barretenberg
noir-prove:
    bb prove -b ./target/circuit.json -w ./target/circuit.gz --write_vk -o target/circuit

# Verify proof using Barretenberg
noir-verify:
    bb verify -i ./target/circuit/public_inputs -p ./target/circuit/proof -k ./target/circuit/vk

# Run full Noir workflow: execute, prove, and verify
noir-full: noir-test noir-execute noir-prove noir-verify
