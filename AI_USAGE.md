# AI usage: dsc26-cyb-w02

## Tools
- Claude (claude.ai chat): helped me understand the task, reviewed my work, and ran extra checks on my code. It also provided first drafts of `tmcheck/core.py`, `tmcheck/__main__.py`, my own tests, and the new threats in `models/rawaj_scoring.yaml`.
 

## What AI got wrong
- `load_model` let a `ValueError` escape. PyYAML raises `ValueError` (not `YAMLError`) for an impossible date such as `2026-13-45`, so the program would crash instead of raising `ModelError`. Claude pointed out this issue while checking my code against the spec. I confirmed it myself: `yaml.safe_load('a: 2026-13-45')` raised `ValueError: month must be in 1..12`. I added `ValueError` to the `except` clause in `load_model`. After the fix, `python -m tmcheck bad.yaml` printed an error message and exited with code 2.

## In my own words
1. A data store has no Spoofing threats because it is a passive component that stores data but does not actively authenticate or represent an identity. Spoofing threats apply to external entities, such as users or processes. The threat is associated with the external entity that accesses the data store, rather than the data store itself.

2. T38, I would fix this threat first because the lack of access control could allow unauthorized users to access.