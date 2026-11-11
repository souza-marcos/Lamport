---
name: Anti-Overengineering & Clean Code Guardrail
description: Enforces YAGNI principles, minimal code changes, and strict scope control to prevent code bloat.
# Author: Senior Engineering Guardrail
--- 
## Context
Codex tends to be "safe by default" by creating robust abstractions, layers, factory patterns, or defensive guards that are completely unnecessary for small tickets or specific tasks. This skill forces Codex to act like a pragmatic senior developer: touch as little as possible, reuse existing code, and avoid turning a 5-minute fix into a mini-refactor.

## Rules of Engagement

1. **The Smallest Change Principle**
   - Make the absolute smallest code change that fully and correctly solves the task.
   - Do not add abstractions, fallbacks, interfaces, generic wrappers, or future-proofing unless explicitly asked.

2. **YAGNI & KISS**
   - If a feature or edge-case is not explicitly in the requirements, do not implement it.
   - Use simple control flow (like `if/else`) instead of design patterns (like Strategy or Factory) if you are only handling 2 or 3 cases.
   - Avoid "separation of concerns" that splits 20 lines of code across 5 new files. Keep simple code localized.

3. **Surgical Refactoring Only**
   - Do not rewrite or refactor surrounding code unless the current implementation is fundamentally broken or impossible to extend.
   - **Reuse** existing utilities, helpers, and functions before writing a single line of new logic.

4. **Execution Protocol**
   - BEFORE writing any code, output a short, bulleted architecture plan:
     - **Files to touch:** [List of files]
     - **Lines of code estimate:** [e.g., ~5 lines]
     - **Complexity justification:** Explain why this is the simplest possible path and why a simpler one doesn't exist.
   - Wait for user confirmation or proceed directly if running in fully autonomous non-interactive mode.

## Example Roasts / Guardrails (Strict Enforcement)
- **Do not wrap:** A single child class does not need an abstract base class.
- **Do not abstract:** A function used in one place does not need a generic wrapper.
- **Do not split:** Do not turn a 5-line functional addition into a new service class.
