"""Torch classifiers for PackGuard FL (PACKGUARD_BRIEF §4: "Model: LR/MLP on
graph features (torch CPU/MPS) — pilot scale; GNN is future work").

Deterministic: no dropout, seeded init + seeded minibatch permutations.
Default seed 20260922 (PACKGUARD_BRIEF §4).
"""
from __future__ import annotations

import random
from typing import Optional, Sequence

import numpy as np
import torch
from torch import nn

__all__ = [
    "DEFAULT_SEED",
    "set_seed",
    "LogisticModel",
    "MLPModel",
    "build_model",
    "clone_params",
    "params_to_cpu_list",
    "local_train",
    "predict_proba",
]

DEFAULT_SEED = 20260922


def set_seed(seed: int = DEFAULT_SEED) -> None:
    """Seed python/numpy/torch (incl. MPS) — called once per run/round."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.backends.mps.is_available():
        try:
            torch.mps.manual_seed(seed)
        except (AttributeError, RuntimeError):  # pragma: no cover - CPU-only box
            pass


class LogisticModel(nn.Module):
    """Logistic regression on the feature vector (single linear unit)."""

    def __init__(self, input_dim: int):
        super().__init__()
        self.linear = nn.Linear(int(input_dim), 1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.linear(x).squeeze(-1)


class MLPModel(nn.Module):
    """One hidden layer (ReLU) — the larger pilot option from the brief."""

    def __init__(self, input_dim: int, hidden_dim: int = 32):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(int(input_dim), int(hidden_dim)),
            nn.ReLU(),
            nn.Linear(int(hidden_dim), 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x).squeeze(-1)


def build_model(model_cfg: dict, input_dim: int) -> nn.Module:
    """Build from a config dict {"type": "lr"|"mlp", "hidden_dim": int}."""
    kind = str(model_cfg.get("type", "lr")).lower()
    if kind == "lr":
        return LogisticModel(input_dim)
    if kind == "mlp":
        return MLPModel(input_dim, int(model_cfg.get("hidden_dim", 32)))
    raise ValueError(f"unknown model type: {kind!r} (expected 'lr' or 'mlp')")


def clone_params(state: Sequence[torch.Tensor]) -> list[torch.Tensor]:
    return [t.detach().clone() for t in state]


def params_to_cpu_list(state_dict: dict) -> list[torch.Tensor]:
    """state_dict -> flat CPU tensor list in the module's registration order.

    Insertion order (NOT alphabetical: 'linear.bias' would sort before
    'linear.weight' and desync with model.parameters()). Every client builds
    the identical architecture, so the order is consistent across clients.
    """
    return [v.detach().cpu().clone() for v in state_dict.values()]


def local_train(
    model: nn.Module,
    X: torch.Tensor,
    y: torch.Tensor,
    epochs: int,
    lr: float,
    batch_size: int,
    global_params: Optional[Sequence[torch.Tensor]] = None,
    mu: float = 0.0,
    seed: int = DEFAULT_SEED,
) -> nn.Module:
    """Local SGD update; appends the FedProx proximal term when mu > 0.

    FedProx (Li et al. 2020): loss += (mu / 2) * ||w - w_global||^2, where
    w_global is the broadcast round-global parameter vector (kept frozen).
    Minibatch permutations come from a dedicated seeded Generator, so the
    update is deterministic given (data, epochs, lr, batch_size, mu, seed).
    """
    if mu > 0 and global_params is None:
        raise ValueError("FedProx (mu>0) requires the broadcast global params")
    opt = torch.optim.SGD(model.parameters(), lr=float(lr))
    gen = torch.Generator().manual_seed(int(seed))
    n = int(X.shape[0])
    for _ in range(max(1, int(epochs))):
        perm = torch.randperm(n, generator=gen)
        for start in range(0, n, max(1, int(batch_size))):
            idx = perm[start : start + int(batch_size)]
            opt.zero_grad()
            logits = model(X[idx])
            loss = nn.functional.binary_cross_entropy_with_logits(
                logits, y[idx].float()
            )
            if mu > 0 and global_params is not None:
                prox = torch.zeros((), dtype=logits.dtype)
                for p, g in zip(model.parameters(), global_params):
                    prox = prox + ((p - g) ** 2).sum()
                loss = loss + (float(mu) / 2.0) * prox
            loss.backward()
            opt.step()
    return model


@torch.no_grad()
def predict_proba(model: nn.Module, X: torch.Tensor) -> np.ndarray:
    """P(malicious) per row (sigmoid of the logit)."""
    model.eval()
    logits = model(X)
    return torch.sigmoid(logits).cpu().numpy().astype(float).ravel()
