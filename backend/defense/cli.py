"""Command line: run the target agent on a task.

    python -m backend.defense.cli run --task "list the files" --sandbox ./work
"""

import argparse

from backend.defense.agent import Agent
from backend.database.audit import AuditLog
from backend.defense.llm import OllamaBackend
from backend.defense.sandbox import Sandbox
from backend.defense.tools import Tools


def main(argv=None):
    parser = argparse.ArgumentParser(prog="agentshield")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Run the target agent on a task")
    run.add_argument("--task", required=True)
    run.add_argument("--sandbox", default="./work")
    run.add_argument("--model", default="qwen2.5")

    args = parser.parse_args(argv)

    if args.command == "run":
        sandbox = Sandbox(args.sandbox)
        tools = Tools(sandbox)
        audit = AuditLog()
        agent = Agent(OllamaBackend(model=args.model), tools, audit)
        result = agent.run(args.task)
        print(f"Session {result.session_id}")
        for step in result.steps:
            status = step["blocked_reason"] or ("ok" if step["ok"] else "failed")
            print(f"  {step['tool']}({step['args']}) -> {status}")
        print(f"FINAL: {result.final_answer}")
        audit.close()


if __name__ == "__main__":
    main()
