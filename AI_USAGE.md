# AI usage: dsc26-cyb-w02

## Tools
- Claude (claude.ai chat): helped me understand the task, reviewed my work, and ran extra checks on my code. It also provided first drafts of `tmcheck/core.py`, `tmcheck/__main__.py`, my own tests, and the new threats in `models/rawaj_scoring.yaml`.
 

## What AI got wrong
- `load_model` let a `ValueError` escape. PyYAML raises `ValueError` (not `YAMLError`) for an impossible date such as `2026-13-45`, so the program would crash instead of raising `ModelError`. Claude pointed out this issue while checking my code against the spec. I confirmed it myself: `yaml.safe_load('a: 2026-13-45')` raised `ValueError: month must be in 1..12`. I added `ValueError` to the `except` clause in `load_model`. After the fix, `python -m tmcheck bad.yaml` printed an error message and exited with code 2.

## In my own words
1. A data store has no Spoofing threats because it passively stores data. Spoofing applies to external entities and processes, so the threat should be assigned to the element being impersonated, as in T8.

2. I would fix T38 first because missing access control could let attackers access sensitive PII in the `feature_store`. Its score is 12 (3 × 4), and it is the only threat identified for this component.