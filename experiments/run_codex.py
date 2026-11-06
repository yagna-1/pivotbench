"""Run PivotBench tasks through the Codex CLI (no API key needed).

Two modes:
  ChatGPT sign-in (OpenAI models):   python3 experiments/run_codex.py --model gpt-5.2-codex
  Local open model via Ollama:       python3 experiments/run_codex.py --oss --model gpt-oss:20b

Each batch is one fresh `codex exec` call (no shared context between batches),
read-only sandbox, final message captured with --output-last-message. Outputs go
to results/opencode/<label>/... in the same format as run_opencode.py, so the
existing analysis scripts work unchanged. Resumable: finished files are skipped.

    python3 experiments/run_codex.py --model gpt-5.2-codex --tasks realistic,mixed,single
    tar czf codex_results.tgz results/opencode/<label>

Note: for a local model, the OpenAI-compatible endpoint of Ollama can also be
used directly, which avoids Codex's own agent prompt:
    OPENCODE_API_KEY=ollama python3 experiments/run_opencode.py \
        --base-url http://localhost:11434/v1 --models gpt-oss:20b
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_opencode import ALL, OUT, parse_array, tasks_for  # noqa: E402

FRAME = ("You are not acting as a coding agent for this task. Do not run commands or edit files. "
         "Adopt the role defined below and reply with the requested JSON only.\n\n"
         "=== ROLE / SYSTEM PROMPT ===\n{system}\n\n=== TASK ===\n{user}")


def codex_call(prompt: str, model: str, oss: bool, timeout: int) -> str:
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "last.txt"
        cmd = ["codex", "exec", "--skip-git-repo-check", "-s", "read-only", "-m", model,
               "--output-last-message", str(out)]
        if oss:
            cmd.append("--oss")
        cmd.append("-")  # prompt on stdin
        r = subprocess.run(cmd, input=prompt, text=True, capture_output=True, timeout=timeout, cwd=td)
        if r.returncode != 0:
            raise RuntimeError(f"codex exit {r.returncode}: {r.stderr[-400:]}")
        return out.read_text() if out.exists() else r.stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--label", default="", help="results folder name (default: model id)")
    ap.add_argument("--oss", action="store_true", help="use Codex's local open-model provider (Ollama/LM Studio)")
    ap.add_argument("--tasks", default=",".join(ALL))
    ap.add_argument("--timeout", type=int, default=900)
    a = ap.parse_args()
    label = a.label or a.model.replace(":", "-").replace("/", "-")
    for t in [t for t in a.tasks.split(",") if t]:
        for system, user, ids, rel in tasks_for(t):
            path = OUT / label / rel
            if path.exists():
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            last = ""
            for attempt in range(3):
                try:
                    last = codex_call(FRAME.format(system=system, user=user), a.model, a.oss, a.timeout)
                    arr = parse_array(last)
                    got = sorted(str(x.get("id")) for x in arr if isinstance(x, dict))
                    if got != sorted(ids):
                        raise ValueError(f"ids mismatch ({len(got)} for {len(ids)})")
                    path.write_text(json.dumps(arr, indent=1))
                    print(f"  ok  {label}/{rel}")
                    break
                except Exception as e:  # noqa: BLE001
                    print(f"  retry {attempt + 1} {rel}: {str(e)[:200]}")
                    time.sleep(10)
            else:
                path.with_suffix(".err.txt").write_text(last)
                print(f"  FAILED {label}/{rel}")
    print(f"done. Attach: tar czf codex_results.tgz results/opencode/{label}")


if __name__ == "__main__":
    main()
