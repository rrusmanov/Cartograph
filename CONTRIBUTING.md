# Contributing to Cartograph

Thanks for your interest. Cartograph is a research-oriented, passive attack-surface tool; contributions
should respect its ethics-by-design posture (see the README).

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Quality gates (run before opening a PR)

```bash
ruff check .        # lint + import order
ruff format .       # formatting
mypy cartograph     # static types (strict)
pytest              # tests
```

CI runs all of the above on every push and PR.

## Adding a passive collector

1. Create `cartograph/collectors/<source>.py`.
2. Subclass `Collector` and implement `async def collect(self, target: str) -> CollectResult`.
3. Emit typed `Node`/`Edge` objects only – never raw source dicts.
4. Cache raw responses so experiments stay reproducible (`self.cache`).
5. Add a unit test that mocks the HTTP layer (`respx`) – do **not** hit live APIs in tests.

## Non-negotiables

- No active scanning, exploitation, brute-forcing, or fuzzing in any default path.
- Any active capability must be gated behind the scope-guard and an explicit flag.
- Tests must not make live network calls.
