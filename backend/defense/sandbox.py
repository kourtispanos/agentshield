"""Sandbox: confine the target agent to a single working directory.

Every file and shell operation is resolved against a sandbox root; anything that
resolves outside the root is rejected before it runs. This is a safety boundary
for running an experimental agent, not protection against a determined attacker -
real isolation is a VM or container.
"""

from pathlib import Path


class SandboxError(Exception):
    """Raised when an operation tries to leave the sandbox."""


class Sandbox:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def resolve(self, relative_path):
        """Resolves a path inside the sandbox, or raises SandboxError.
        Compares against the root's children (not a string prefix) so that
        '../../etc/passwd' can't sneak out."""
        candidate = (self.root / relative_path).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise SandboxError(f"Path escapes sandbox: {relative_path}")
        return candidate
