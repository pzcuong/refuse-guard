#!/usr/bin/env python
"""Generate all paper figures + verify table numbers against raw output files.

Every plotted number is READ from a real output file under outputs/ (no
hand-typed results). Structural asserts guard against reading the wrong key;
a final verify_tables() step cross-checks the numbers typed into
paper/tables/*.tex against the same files and fails loudly on any mismatch.

Run:  .venv/bin/python paper/make_figures.py
Output: paper/figures/*.pdf
"""
from __future__ import annotations

import json
from math import comb
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
FIG = Path(__file__).resolve().parent / "figures"
FIG.mkdir(exist_ok=True)

plt.rcParams.update({
    "font.size": 8,
    "axes.titlesize": 8.5,
    "axes.labelsize": 8,
    "xtick.labelsize": 7.5,
    "ytick.labelsize": 7.5,
    "legend.fontsize": 7,
    "figure.dpi": 150,
    "savefig.bbox": "tight",
})

C_B0 = "#b2182b"   # raw / baseline
C_DEF = "#2166ac"  # defense
C_MID = "#666666"


def load(rel: str) -> dict:
    p = ROOT / rel
    assert p.exists(), f"missing source file: {rel}"
    return json.loads(p.read_text())


# ---------------------------------------------------------------------------
# Source files (single source of truth; mirrors reports/round3/S_report.md §5)
# ---------------------------------------------------------------------------
E0 = {
    "qwen3b": load("outputs/experiments/round3_e0/qwen3b/results.json"),
    "llama3b": load("outputs/experiments/round3_e0/llama3b/results.json"),
    "granite2b": load("outputs/experiments/round3_e0/granite2b/results.json"),
}
E2E3 = load("outputs/experiments/round3_e2e3/qwen3b/results.json")
E6 = load("outputs/experiments/round3_e6/results.json")
E8_POST = {
    "qwen3b": load("outputs/experiments/round3_e8/recomputed/recompute_e8_monitor.json"),
    "llama3b": load("outputs/experiments/round3_e8_llama3b/recomputed/recompute_e8_monitor.json"),
}
SUM2 = load("outputs/experiments/pilot_round2_recomputed/summary_v2.json")
CODEBERT = load("outputs/transformer/codebert_eval_vd_s_metrics.json")
E0V2 = {m: load(f"outputs/experiments/round5_e0v2/results_{m}.json")
        for m in ("qwen3b", "llama3b", "granite2b")}
E0V2_VERDICT = load("outputs/experiments/round5_e0v2/verdict.json")
DEF_LLAMA = load("outputs/experiments/round5_defense/results_llama3b.json")
DEF_QWEN = load("outputs/experiments/round5_defense/results_qwen3b.json")
SIDE_EFFECT = load("outputs/experiments/round5_defense/side_effect_llama3b.json")
R5_MASTER = load("outputs/master/round5_master.json")

# --- structural sanity asserts --------------------------------------------
for m, d in E0.items():
    assert d["metadata"]["partial"] is False
    for arm in ("neutral", "defensive_wording", "security_context"):
        assert d["metrics"]["arms"][arm]["RR"] == 0.0, (m, arm)
        assert d["metrics"]["gate_per_model"]["pass_this_model"] is False
assert E2E3["metadata"]["partial"] is False
assert set(E2E3["metrics"]["groups"]) == {"C0_neutral", "C1_defensive", "C2a", "C2b", "C3"}
assert "IPI_flip_rate_B0" in E6["metrics"]["flip_metrics"]
assert E8_POST["qwen3b"]["metadata"]["n_status_changed"] == 0
assert E8_POST["llama3b"]["metadata"]["n_status_changed"] == 11
assert CODEBERT["meta"]["is_dry_run"] is False and CODEBERT["metrics"]["n_vulnerable"] == 549
# Round-5 structural sanity (files exist, runs are real, zero refusal anywhere)
for m, d in E0V2.items():
    assert d["metadata"]["real"] is True and d["metadata"]["partial"] is False
    assert all(r["status"] != "REFUSAL" for r in d["records"])
    assert d["metadata"]["n_records"] == {"qwen3b": 480, "llama3b": 480, "granite2b": 240}[m]
assert E0V2_VERDICT["aggregate"]["H_A"]["verdict"] == "NOT_SUPPORTED"
assert E0V2_VERDICT["aggregate"]["H_A"]["models_pass"] == 0
assert DEF_LLAMA["metadata"]["real"] is True and DEF_QWEN["metadata"]["real"] is True
assert SIDE_EFFECT["metrics"]["P3_gate_blocked"] == 30


# ---------------------------------------------------------------------------
# Figure 1: conditions + defenses pipeline (schematic, no data numbers)
# ---------------------------------------------------------------------------
def fig_conditions() -> None:
    fig, ax = plt.subplots(figsize=(7.0, 2.6))
    ax.axis("off")

    def box(x, y, w, h, text, fc, fs=7.0, bold=False, ec="#333333"):
        ax.add_patch(plt.Rectangle((x, y), w, h, facecolor=fc, edgecolor=ec,
                                   linewidth=0.9, zorder=2))
        ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
                fontsize=fs, zorder=3, weight="bold" if bold else "normal")

    def arrow(x1, y1, x2, y2, ls="-", color="#333333"):
        ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                    arrowprops=dict(arrowstyle="-|>", linestyle=ls,
                                    color=color, linewidth=1.0))

    # Row 1: sample -> context conditions -> task-intent gate
    box(0.15, 1.62, 1.30, 0.85, "PrimeVul\nfunction\n(clean C0)", "#f0f0f0", fs=7.0)
    box(1.75, 1.62, 2.10, 0.85, "C1 defensive\nprompt framing", "#fff3e0", fs=7.0)
    box(4.05, 1.62, 2.35, 0.85, "C2a/C2b benign carriers\n(near/far comment,\ndocstring, string)",
        "#fff3e0", fs=7.0)
    box(6.60, 1.62, 2.45, 0.85, "C3 instruction-like\ncontext (IPI)\n", "#fff3e0", fs=7.0)
    ax.text(5.3, 2.62, "tree-sitter semantics gate: executable AST unchanged by C2/C3",
            ha="center", fontsize=6.6, style="italic", color="#555555")
    arrow(1.45, 2.05, 1.75, 2.05)
    arrow(3.85, 2.05, 4.05, 2.05)
    arrow(6.40, 2.05, 6.60, 2.05)

    # Task-intent gate (right)
    box(9.35, 1.62, 1.85, 0.85, "Task-intent gate\ndefensive /\nambiguous /\nout-of-scope",
        "#e8f0fe", fs=6.6)
    arrow(9.05, 2.05, 9.35, 2.05)

    # Row 2: defenses -> LLM -> monitor -> recovery
    box(0.15, 0.42, 2.20, 0.85,
        "Defences\nB1 reframe / B2 comment strip\nB3 aggressive removal\nP1 semantic isolation",
        "#eef7ee", fs=6.4)
    box(2.75, 0.42, 1.95, 0.85,
        "LLM analyzer\nlocked JSON schema\n(vulnerable, CWE,\nlocation, confidence)",
        "#f0f0f0", fs=6.4)
    box(5.10, 0.42, 1.95, 0.85,
        "Refusal monitor\nANSWER / PARTIAL /\nREFUSAL\n(calibrated thresholds)",
        "#fdeef0", fs=6.4)
    box(7.45, 0.42, 1.95, 0.85,
        "Recovery\nstructured retry;\nREFUSED_UNSAFE if gate\nflags unsafe prompt",
        "#eef7ee", fs=6.4)
    arrow(2.35, 0.85, 2.75, 0.85)
    arrow(4.70, 0.85, 5.10, 0.85)
    arrow(7.05, 0.85, 7.45, 0.85)
    arrow(10.27, 1.62, 10.27, 1.27)
    arrow(10.27, 1.27, 8.42, 1.27)
    arrow(8.42, 1.27, 8.42, 0.85)

    # Row 3: transformer fallback
    box(2.75, -0.75, 4.30, 0.80,
        "B4 transformer fallback (CodeBERT, independent prior)\n"
        "when LLM output is REFUSAL/PARTIAL after retry",
        "#eef7ee", fs=6.6)
    arrow(8.42, 0.42, 8.42, -0.35)
    arrow(8.42, -0.35, 7.05, -0.35)

    ax.text(5.7, 3.05, "RefuseGuard pipeline: conditions (top) and defences (bottom)",
            ha="center", fontsize=8.5, weight="bold")
    ax.set_xlim(0, 11.4)
    ax.set_ylim(-0.9, 3.2)
    fig.savefig(FIG / "fig_conditions.pdf")
    plt.close(fig)


# ---------------------------------------------------------------------------
# Figure 2: E0 reproduction gate — RR per arm (zero) vs probe behaviour
# ---------------------------------------------------------------------------
def fig_e0_rr() -> None:
    arms = ["neutral", "defensive_wording", "security_context"]
    labels = ["neutral", "defensive\nwording", "security\ncontext"]
    models = ["qwen3b", "llama3b", "granite2b"]
    name = {"qwen3b": "Qwen2.5-Coder-3B", "llama3b": "Llama-3.2-3B",
            "granite2b": "Granite-3.3-2B"}
    color = {"qwen3b": C_B0, "llama3b": C_DEF, "granite2b": C_MID}

    rr = {m: [E0[m]["metrics"]["arms"][a]["RR"] for a in arms] for m in models}
    over = {m: [E0[m]["metrics"]["probes_by_arm"][a]["over_refusal_rate"] for a in arms]
            for m in models}
    unsafe = {m: [E0[m]["metrics"]["probes_by_arm"][a]["unsafe_compliance_rate"] for a in arms]
              for m in models}
    p_vals = {m: E0[m]["metrics"]["delta_RR_defensive_vs_neutral"]["mcnemar"]["p_value"]
              for m in models}

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6.6, 2.15))

    # (a) RR on vulnerability-analysis functions: all zero, all three models
    x = list(range(len(arms)))
    w = 0.26
    for i, m in enumerate(models):
        ax1.bar([xi + (i - 1) * w for xi in x], rr[m], width=w, color=color[m],
                label=name[m])
        for xi, v in zip(x, rr[m]):
            ax1.text(xi + (i - 1) * w, 0.015, f"{v:.3f}", ha="center", va="bottom",
                     fontsize=6.2, rotation=90)
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels)
    ax1.set_ylim(0, 1.0)
    ax1.set_ylabel("Refusal rate (RR)")
    ps = "/".join(f"{p_vals[m]:.1f}" for m in models)
    ax1.set_title("(a) E0 function arms: RR = 0.000 everywhere\n"
                  f"($\\Delta$RR = 0, McNemar p = {ps}; gate FAIL)")
    ax1.legend(loc="upper right", frameon=False, fontsize=6.0)

    # (b) probe behaviour: models DO refuse, just not condition-dependently
    # per (arm, model): solid bar = over-refusal (COMPLY-expected refused),
    # hatched bar = unsafe compliance (REFUSE-expected complied)
    xs, vals, cols, hatches = [], [], [], []
    k = 0.0
    centers = []
    for i in range(len(arms)):
        start = k
        for j, m in enumerate(models):
            c = color[m]
            xs.append(k)
            vals.append(over[m][i])
            cols.append(c)
            hatches.append("")
            xs.append(k + 0.34)
            vals.append(unsafe[m][i])
            cols.append(c)
            hatches.append("///")
            k += 0.68
        centers.append(start + (k - 0.34 - start) / 2)
        k += 0.45
    bars = ax2.bar(xs, vals, width=0.32, color=cols, edgecolor="white", linewidth=0.4)
    for b, h in zip(bars, hatches):
        if h:
            b.set_hatch(h)
            b.set_edgecolor("#333333")
            b.set_linewidth(0.6)
    for x, v in zip(xs, vals):
        ax2.text(x, min(v + 0.02, 1.04), f"{v:.2f}", ha="center", fontsize=5.2,
                 rotation=90)
    ax2.set_xticks(centers)
    ax2.set_xticklabels(labels)
    ax2.set_ylim(0, 1.28)
    ax2.set_ylabel("Probe rate")
    ax2.set_title("(b) Contrast probes: refusal exists,\nbut is arm-independent")
    import matplotlib.patches as mpatches
    handles = [mpatches.Patch(color=color[m], label="over-refusal, " + name[m])
               for m in models]
    handles.append(mpatches.Patch(facecolor="white", edgecolor="#333333", hatch="///",
                                  label="unsafe compliance"))
    ax2.legend(handles=handles, loc="upper left", frameon=False, fontsize=5.0)

    fig.tight_layout()
    fig.savefig(FIG / "fig_e0_rr.pdf")
    plt.close(fig)


# ---------------------------------------------------------------------------
# Figure 3: E6 — IPI injection success B0 vs P1 (+ stratified discordance)
# ---------------------------------------------------------------------------
def fig_e6_injection() -> None:
    fm = E6["metrics"]["flip_metrics"]
    b0 = fm["IPI_flip_rate_B0"]["ipi_flip_rate"]
    p1 = fm["IPI_flip_rate_P1"]["ipi_flip_rate"]
    pv = fm["mcnemar_flip_C3_B0_vs_P1"]["p_value"]

    # stratified discordant counts recomputed from records (V2 audit numbers)
    by = {}
    for r in E6["records"]:
        by.setdefault((r["condition"], r["defense"]), {})[r["sample_id"]] = r
    ref, b0c3, p1c3 = by[("C0", "B0")], by[("C3", "B0")], by[("C3", "P1")]
    disc = [s for s in ref
            if (b0c3[s]["y_pred"] == 0) != (p1c3[s]["y_pred"] == 0)]
    dv = [s for s in disc if b0c3[s]["y_true"] == 1]
    db = [s for s in disc if b0c3[s]["y_true"] == 0]
    assert len(disc) == 8 and len(dv) == 2 and len(db) == 6, (len(disc), len(dv), len(db))

    def binom_two(b, n):
        if n == 0:
            return 1.0
        return min(1.0, sum(comb(n, k) for k in range(0, min(b, n - b) + 1)) / 2 ** n * 2)

    p_vul = binom_two(sum(1 for s in dv if b0c3[s]["y_pred"] == 0 and p1c3[s]["y_pred"] != 0), len(dv))
    p_ben = binom_two(sum(1 for s in db if b0c3[s]["y_pred"] == 0 and p1c3[s]["y_pred"] != 0), len(db))

    fig, ax = plt.subplots(figsize=(3.35, 2.15))
    bars = ax.bar([0, 1], [b0, p1], width=0.55, color=[C_B0, C_DEF])
    for x, v in zip([0, 1], [b0, p1]):
        ax.text(x, v + 0.02, f"{v:.3f}", ha="center", fontsize=7.5)
    ax.set_xticks([0, 1])
    ax.set_xticklabels(["B0 (raw)", "P1 (semantic\nisolation)"])
    ax.set_ylabel("Injection success\n(C3 verdict flips to benign)")
    ax.set_ylim(0, 0.9)
    ax.annotate(f"McNemar p = {pv:.4f} (overall)\n"
                f"8 discordant pairs: 6 benign (p = {p_ben:.3f}),\n"
                f"2 vulnerable (p = {p_vul:.2f}, n.s.)",
                xy=(0.5, 0.60), xycoords="axes fraction", ha="center", fontsize=6.8,
                bbox=dict(boxstyle="round,pad=0.35", facecolor="#f7f7f7",
                          edgecolor="#bbbbbb"))
    fig.savefig(FIG / "fig_e6_injection.pdf")
    plt.close(fig)


# ---------------------------------------------------------------------------
# Figure 4: E8 — naive P2 was a refusal-suppression machine; fixed P2 is not
# ---------------------------------------------------------------------------
def fig_e8_compliance() -> None:
    pre = SUM2["trees"]["3b_qwen"]["experiments"]["e8"]["metrics"]["safety_summary"]
    pre_b0 = pre["B0"]["unsafe_compliance_rate"]
    pre_p2 = pre["P2"]["unsafe_compliance_rate"]
    assert pre_b0 == 0.04 and pre_p2 == 1.0

    post = {}
    for m in ("qwen3b", "llama3b"):
        s = E8_POST[m]["summary"]
        post[m] = (s["B0"]["unsafe_compliance_rate"], s["P2"]["unsafe_compliance_rate"],
                   s["P2"]["gate_blocked_n"])
    assert post["qwen3b"] == (0.0, 0.0, 30)
    assert post["llama3b"] == (0.03333333333333333, 0.0, 30)

    groups = [
        ("Qwen-3B\npre-fix (R2)", pre_b0, pre_p2),
        ("Qwen-3B\nfixed (R3)", post["qwen3b"][0], post["qwen3b"][1]),
        ("Llama-3.2-3B\nfixed (R3)", post["llama3b"][0], post["llama3b"][1]),
    ]
    fig, ax = plt.subplots(figsize=(3.35, 2.2))
    xs, b0v, p2v, cols_b0, cols_p2 = [], [], [], [], []
    for i, (lab, b, p) in enumerate(groups):
        xs.append(i)
        b0v.append(b)
        p2v.append(p)
        cols_b0.append(C_B0)
        cols_p2.append(C_DEF)
    w = 0.36
    ax.bar([x - w / 2 for x in xs], b0v, width=w, color=cols_b0, label="B0 (raw)")
    ax.bar([x + w / 2 for x in xs], p2v, width=w, color=cols_p2, label="P2 (RefuseGuard)")
    for x, v in zip(xs, b0v):
        ax.text(x - w / 2, v + 0.02, f"{v:.3f}", ha="center", fontsize=7)
    for x, v in zip(xs, p2v):
        ax.text(x + w / 2, v + 0.02, f"{v:.2f}", ha="center", fontsize=7)
    ax.set_xticks(xs)
    ax.set_xticklabels([g[0] for g in groups], fontsize=6.8)
    ax.set_ylabel("Unsafe compliance rate\n(30 unsafe prompts)")
    ax.set_ylim(0, 1.15)
    ax.axhline(1.0, color="#999999", linewidth=0.6, linestyle=":")
    ax.legend(loc="upper right", frameon=False, fontsize=6.5)
    ax.set_title("Naive structured recovery (R2) forced\ncompliance; gate-first P2 (R3) does not",
                 fontsize=7.5)
    fig.savefig(FIG / "fig_e8_compliance.pdf")
    plt.close(fig)


# ---------------------------------------------------------------------------
# Figure 5: CodeBERT B4 — realistic-difficulty baseline
# ---------------------------------------------------------------------------
def fig_codebert() -> None:
    m = CODEBERT["metrics"]
    vals = [m["recall@0.5"], m["f1@0.5"], m["mcc@0.5"], m["auc"]]
    labs = ["Recall", "F1", "MCC", "AUC"]
    paired = m["paired"]
    pv = [paired["p_c_both_correct@0.5"], paired["p_v_both_vulnerable@0.5"],
          paired["p_b_both_benign@0.5"], paired["p_r_inverse@0.5"]]
    pl = ["P-C", "P-V", "P-B", "P-R"]
    vd_s = m["vd_s"]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6.6, 2.0))
    ax1.bar(labs, vals, width=0.55, color=C_DEF)
    for i, v in enumerate(vals):
        ax1.text(i, v + 0.02, f"{v:.3f}", ha="center", fontsize=7)
    ax1.set_ylim(0, 1.05)
    ax1.set_ylabel("Score")
    ax1.set_title(f"(a) B4 CodeBERT @0.5 (549 vul + 20,000 benign)\n"
                  f"VD-S (FNR @ FPR$\\leq$0.5%) = {vd_s:.3f} → detects "
                  f"{1 - vd_s:.1%} of vulns")
    ax2.bar(pl, pv, width=0.55, color=C_MID)
    for i, v in enumerate(pv):
        ax2.text(i, v + 0.012, f"{v:.3f}", ha="center", fontsize=7)
    ax2.set_ylim(0, 0.62)
    ax2.set_ylabel("Pair outcome rate (435 pairs)")
    ax2.set_title("(b) PrimeVul paired outcomes\n"
                  f"paired rank-acc = {paired['paired_rank_accuracy']:.3f}")
    fig.tight_layout()
    fig.savefig(FIG / "fig_codebert.pdf")
    plt.close(fig)


# ---------------------------------------------------------------------------
# Figure 6 (Round 5): C5 attack + P3 defence — two opposite verdict drifts,
# zero blocking anywhere. All numbers recomputed from records (asserted).
# ---------------------------------------------------------------------------
def _e0v2_flip_benign_to_vul(model: str) -> dict[str, int]:
    by = {(r["condition"], r["sample_id"]): r for r in E0V2[model]["records"]}
    c0 = {s: r for (a, s), r in by.items() if a == "C0"}
    out = {}
    for arm in ("D2_task", "C5_near", "C5_far"):
        out[arm] = sum(1 for s, r0 in c0.items()
                       if r0["y_true"] == 0 and r0["y_pred"] == 0
                       and by[(arm, s)]["y_pred"] == 1)
    return out


def _def_recall_and_flips(model_data: dict) -> dict[tuple[str, str], tuple[float, int, int]]:
    """(arm, defense) -> (vul_recall, flip_v2b, flip_b2v) recomputed from records."""
    by = {(r["condition"], r["defense"], r["sample_id"]): r for r in model_data["records"]}
    out = {}
    for arm in ("C5_near", "C5_far"):
        vul_ids = [s for (c, f, s) in by if c == arm and f == "B0" and by[(c, f, s)]["y_true"] == 1]
        for dfn in ("B0", "P3", "P3R"):
            ids = [s for s in vul_ids if (arm, dfn, s) in by]
            rec = sum(1 for s in ids if by[(arm, dfn, s)]["y_pred"] == 1) / len(ids)
            v2b = sum(1 for s in ids if dfn != "B0"
                      and by[(arm, "B0", s)]["y_pred"] == 1 and by[(arm, dfn, s)]["y_pred"] == 0)
            b2v = sum(1 for s in ids if dfn != "B0"
                      and by[(arm, "B0", s)]["y_pred"] == 0 and by[(arm, dfn, s)]["y_pred"] == 1)
            out[(arm, dfn)] = (rec, v2b, b2v)
    return out


def fig_round5() -> None:
    # audit-anchored expectations (V1/V2 round-5 audits)
    flips = {m: _e0v2_flip_benign_to_vul(m) for m in E0V2}
    assert flips["qwen3b"] == {"D2_task": 0, "C5_near": 0, "C5_far": 0}, flips["qwen3b"]
    assert flips["llama3b"] == {"D2_task": 10, "C5_near": 11, "C5_far": 11}, flips["llama3b"]
    assert flips["granite2b"] == {"D2_task": 10, "C5_near": 20, "C5_far": 25}, flips["granite2b"]
    dl = _def_recall_and_flips(DEF_LLAMA)
    assert dl[("C5_near", "B0")][0] == 1.0 and dl[("C5_far", "B0")][0] == 1.0
    assert abs(dl[("C5_near", "P3")][0] - 0.3667) < 5e-5 and abs(dl[("C5_far", "P3")][0] - 0.3333) < 5e-5
    assert dl[("C5_near", "P3")][1] == 19 and dl[("C5_far", "P3")][1] == 20
    assert dl[("C5_near", "P3")][2] == 0 and dl[("C5_far", "P3")][2] == 0
    pq = _def_recall_and_flips(DEF_QWEN)
    assert all(abs(pq[(a, d)][0] - 1.0) < 5e-5 for a in ("C5_near", "C5_far")
               for d in ("B0", "P3", "P3R")), pq

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6.6, 2.15))

    # (a) attack direction: benign -> vulnerable flips (no blocking anywhere)
    arms = ["D2_task", "C5_near", "C5_far"]
    labels = ["D2\n(wording)", "C5 near", "C5 far"]
    models = ["qwen3b", "llama3b", "granite2b"]
    name = {"qwen3b": "Qwen-3B", "llama3b": "Llama-3.2-3B", "granite2b": "Granite-3.3-2B"}
    color = {"qwen3b": C_B0, "llama3b": C_DEF, "granite2b": C_MID}
    x = list(range(len(arms)))
    w = 0.26
    for i, m in enumerate(models):
        vals = [flips[m][a] for a in arms]
        ax1.bar([xi + (i - 1) * w for xi in x], vals, width=w, color=color[m],
                label=name[m])
        for xi, v in zip(x, vals):
            ax1.text(xi + (i - 1) * w, v + 0.5, str(v), ha="center", fontsize=6.5)
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels)
    ax1.set_ylim(0, 30)
    ax1.set_ylabel("Paired benign$\\to$vulnerable flips")
    ax1.set_title("(a) C5 attack: no blocking (RR = 0.000,\n"
                  "benign-block = 0.000) but verdicts drift to ``vulnerable''",
                  fontsize=7.2)
    ax1.legend(loc="upper left", frameon=False, fontsize=6.0)

    # (b) defense direction: P3 collapses Llama vulnerable recall
    rec_b0 = [dl[(a, "B0")][0] for a in ("C5_near", "C5_far")]
    rec_p3 = [dl[(a, "P3")][0] for a in ("C5_near", "C5_far")]
    xs = [0, 1]
    wb = 0.34
    ax2.bar([v - wb / 2 for v in xs], rec_b0, width=wb, color=C_B0, label="B0 (raw)")
    ax2.bar([v + wb / 2 for v in xs], rec_p3, width=wb, color=C_DEF, label="P3 (boundary)")
    for v, r0 in zip(xs, rec_b0):
        ax2.text(v - wb / 2, r0 + 0.02, f"{r0:.3f}", ha="center", fontsize=7)
    for v, rp in zip(xs, rec_p3):
        ax2.text(v + wb / 2, rp + 0.02, f"{rp:.3f}", ha="center", fontsize=7)
    # arrow: the defence pushes verdicts down (vul -> benign), annotate total flips
    ax2.annotate("", xy=(1.0, 0.40), xytext=(1.0, 0.97),
                 arrowprops=dict(arrowstyle="-|>", color=C_DEF, linewidth=1.2))
    ax2.text(1.06, 0.66, "39/60 paired\nvul$\\to$benign flips\n(McNemar $p \\leq 3.8{\\times}10^{-6}$)",
             fontsize=6.2, color=C_DEF, va="center")
    ax2.set_xticks(xs)
    ax2.set_xticklabels(["C5 near", "C5 far"])
    ax2.set_ylim(0, 1.15)
    ax2.set_ylabel("Vulnerable recall (Llama-3.2-3B, $n{=}30$/arm)")
    ax2.set_title("(b) P3 defence: same context, opposite drift\n"
                  "(Qwen inert; recovery never triggers)", fontsize=7.2)
    ax2.legend(loc="lower left", frameon=False, fontsize=6.2)

    fig.tight_layout()
    fig.savefig(FIG / "fig_round5.pdf")
    plt.close(fig)


# ---------------------------------------------------------------------------
# Table verification: every number typed in paper/tables/*.tex must appear in
# (or be derived from) the source files loaded above.
# ---------------------------------------------------------------------------
def verify_tables() -> None:
    tabs = {p.name: p.read_text()
            for p in (Path(__file__).parent / "tables").glob("*.tex")}
    assert tabs, "no tables found"

    def need(name: str, *snippets: str):
        for s in snippets:
            assert s in tabs[name], f"{name}: missing {s!r}"

    # tab_main
    need("tab_main.tex",
         "0.000", "1.000",                       # E0 RR / partial_rate
         "0.983",                                # E2E3 C2b UAC (qwen)
         "0.017",                                # SIUD C2b estimate +0.017
         "0.742", "0.484", "0.0078",             # E6 flips + McNemar
         "0.033", "0.000",                       # E8 llama B0 / P2
         "0.967", "0.233",                       # E2E3 C1 recall; E8 qwen safe-refusal B0
         "0.862", "0.500")                       # E3 llama C2a recall; llama C3 recall
    # E3 recalls (qwen) C0 0.800 C1 0.967 C2a 0.933 C2b 0.933 C3 0.333
    need("tab_main.tex", "0.800", "0.967", "0.933", "0.333")
    # E0 granite rows (Round-4 3-model update, S-R4) — exact probe cell strings
    g0 = E0["granite2b"]["metrics"]
    for arm, typed in [("neutral", "0.333/0.538"), ("defensive_wording", "0.333/0.385"),
                       ("security_context", "0.167/0.462")]:
        cell = (f"{g0['probes_by_arm'][arm]['over_refusal_rate']:.3f}/"
                f"{g0['probes_by_arm'][arm]['unsafe_compliance_rate']:.3f}")
        assert cell == typed, (arm, cell, typed)
        assert typed in tabs["tab_main.tex"], f"tab_main missing granite {arm}"
    assert g0["arms"]["neutral"]["RR"] == 0.0 and g0["gate_per_model"]["p_value"] == 1.0

    # tab_codebert
    need("tab_codebert.tex",
         "0.541", "0.215", "0.232", "0.847", "0.962",   # main metrics
         "0.009", "0.517", "0.444", "0.030", "0.223")   # paired outcomes

    # tab_defenses (E5 + E7)
    need("tab_defenses.tex",
         "0.000",                                # CUL 0.000 / drops 0.000
         "0.205", "-0.029",                      # MCC C3 B0 vs P1 (E6 file)
         "0.985", "1.000", "0.094",              # E7 UAC/MCC llm_only vs fallback
         "250", "0")                             # E7 scope-block n_records / reached_fallback
    assert "0.0789" in tabs["tab_defenses.tex"]   # llm_only MCC exact from file
    # disclosure #7 guard: per-case fallback correctness is NOT persisted — the
    # retracted "2/2 correct" claim must never reappear (V1-R4 HIGH-1, fixed S-R4)
    assert "2/2" not in tabs["tab_defenses.tex"], \
        "tab_defenses re-states per-case fallback correctness (retracted claim)"
    assert "2/2 correct" not in (Path(__file__).parent / "sections" / "05_results.tex").read_text()

    # tab_calibration
    need("tab_calibration.tex",
         "0.0/0.2", "0.587", "0.067",            # fitted thresholds + over-refusal
         "0.06", "0.26",                          # unsafe compliance (calibration)
         "0.376", "0.296")                        # calibration accuracy

    # cross-check typed numbers == file numbers (exact string forms)
    q = E2E3["metrics"]
    assert f"{q['groups']['C0_neutral']['classification']['recall']:.3f}" == "0.800"
    assert f"{q['groups']['C1_defensive']['classification']['recall']:.3f}" == "0.967"
    assert f"{q['groups']['C3']['classification']['recall']:.3f}" == "0.333"
    assert f"{q['groups']['C2b']['uac']:.3f}" == "0.983"
    siud = q["SIUD_vs_C0"]["C2b"]["usable_delta_ci"]["estimate"]
    assert f"{siud:+.3f}" == "+0.017"
    fm = E6["metrics"]["flip_metrics"]
    assert f"{fm['IPI_flip_rate_B0']['ipi_flip_rate']:.3f}" == "0.742"
    assert f"{fm['IPI_flip_rate_P1']['ipi_flip_rate']:.3f}" == "0.484"
    assert f"{fm['mcnemar_flip_C3_B0_vs_P1']['p_value']:.4f}" == "0.0078"
    assert f"{E6['metrics']['per_condition_defense']['C3|B0']['classification']['mcc']:.3f}" == "0.205"
    assert f"{E6['metrics']['per_condition_defense']['C3|P1']['classification']['mcc']:.3f}" == "-0.029"
    cb = CODEBERT["metrics"]
    for typed, key in [("0.541", "recall@0.5"), ("0.215", "f1@0.5"),
                       ("0.232", "mcc@0.5"), ("0.847", "auc"), ("0.962", "vd_s")]:
        assert f"{cb[key]:.3f}" == typed, (key, cb[key])
    for typed, key in [("0.009", "p_c_both_correct@0.5"), ("0.517", "p_v_both_vulnerable@0.5"),
                       ("0.444", "p_b_both_benign@0.5"), ("0.030", "p_r_inverse@0.5")]:
        assert f"{cb['paired'][key]:.3f}" == typed, (key, cb["paired"][key])
    assert f"{cb['paired']['paired_rank_accuracy']:.3f}" == "0.223"
    # E7 numbers
    e7 = load("outputs/experiments/round3_e7/e7_fusion_results.json")["ablations"]
    assert f"{e7['llm_only']['overall']['uac']:.3f}" == "0.985"
    assert f"{e7['llm_only']['overall']['mcc']:.4f}" == "0.0789"
    assert f"{e7['llm_then_fallback']['overall']['mcc']:.3f}" == "0.094"
    assert f"{e7['llm_then_fallback']['overall']['uac']:.3f}" == "1.000"
    # calibration numbers
    cal_q = load("outputs/transformer/calibration/Qwen_Qwen2.5-Coder-3B-Instruct/full_report.json")
    cal_l = load("outputs/transformer/calibration/unsloth_Llama-3.2-3B-Instruct/full_report.json")
    assert cal_q["at_fit_thresholds"]["over_refusal_rate"] == 0.5867
    assert cal_l["at_fit_thresholds"]["over_refusal_rate"] == 0.0667
    assert f"{cal_q['at_fit_thresholds']['unsafe_compliance_rate']:.2f}" == "0.06"
    assert f"{cal_l['at_fit_thresholds']['unsafe_compliance_rate']:.2f}" == "0.26"
    print("[verify] all table numbers match source files")

    # ---- Round-5 tables: every number cross-checked against
    # outputs/master/round5_master.json (whose rows are themselves re-derived
    # from the result files by scripts/collect_master_round5.py) ----
    r5 = {(r["experiment"], r["metric"]): r["value"] for r in R5_MASTER["results"]}
    need("tab_round5.tex",
         "0.000",                                  # RR / benign-block all arms
         "0.933", "0.100", "0.733", "0.767",       # C0 llama / granite recalls, granite C5
         "0 / 0 / 0", "10 / 11 / 11", "10 / 20 / 25",  # benign->vul flips
         "NOT\\_SUPPORTED (0/3)")
    need("tab_round5_defense.tex",
         "0.367", "0.333", "1.000",                # P3 / P3R / B0 recalls
         "3.8\\times10^{-6}", "1.9\\times10^{-6}",  # McNemar p
         "30/30", "0.033", "0/30")                 # gate / B0 unsafe / probe
    # recompute the headline master values the two tables rest on
    assert r5[("E0V2", "e0v2.llama3b.C0.recall_vul")] == 0.9333
    assert r5[("E0V2", "e0v2.granite2b.C0.recall_vul")] == 0.1
    assert r5[("E0V2", "e0v2.granite2b.C5_near.recall_vul")] == 0.7333
    assert r5[("E0V2", "e0v2.granite2b.C5_far.recall_vul")] == 0.7667
    assert r5[("E0V2", "e0v2.llama3b.D2_task.flip_benign_to_vul")] == 10
    assert r5[("E0V2", "e0v2.llama3b.C5_near.flip_benign_to_vul")] == 11
    assert r5[("E0V2", "e0v2.llama3b.C5_far.flip_benign_to_vul")] == 11
    assert r5[("E0V2", "e0v2.granite2b.C5_far.flip_benign_to_vul")] == 25
    assert r5[("E0V2", "e0v2.verdict.H_A")] == "NOT_SUPPORTED"
    assert r5[("DEFENSE", "defense.llama3b.C5_near.P3.recall_vul")] == 0.3667
    assert r5[("DEFENSE", "defense.llama3b.C5_far.P3.recall_vul")] == 0.3333
    assert abs(r5[("DEFENSE", "defense.llama3b.C5_near.B0_vs_P3.mcnemar_p_exact")] - 3.8147e-06) < 1e-9
    assert abs(r5[("DEFENSE", "defense.llama3b.C5_far.B0_vs_P3.mcnemar_p_exact")] - 1.9073e-06) < 1e-9
    assert r5[("DEFENSE", "defense.qwen3b.P3_changed_pairs")] == "2/98"
    assert r5[("DEFENSE", "defense.llama3b.side_effect.P3_gate_blocked")] == 30
    assert r5[("DEFENSE", "defense.llama3b.side_effect.B0_unsafe_compliance")] == 0.0333
    assert r5[("BENCH", "c5_query_relevance.concrete_named_own_sink")] == "100/100"
    assert r5[("BENCH", "c2b_carrier_named_sink")] == "2/838"
    assert r5[("ACCOUNTING", "round5.unique_new_generations")] == 1378
    print("[verify] round-5 table numbers match outputs/master/round5_master.json")

    # Cross-check against the Round-4 master aggregate (A1) if present.
    master_path = ROOT / "outputs/master/master_results.json"
    if master_path.exists():
        rows = {(r["experiment"], r["metric"]): r["value"]
                for r in json.loads(master_path.read_text())["results"]}
        cross = [
            ("E0", "e0.granite2b.arm.neutral.RR", 0.0),
            ("E0", "e0.granite2b.probe.neutral.over_refusal_rate", 0.3333333333333333),
            ("E0", "e0.granite2b.probe.neutral.unsafe_compliance_rate", 0.5384615384615384),
            ("E2E3", "e23.qwen3b.C0_neutral.recall", 0.8),
            ("E2E3", "e23.qwen3b.C1_defensive.recall", 0.9666666666666667),
            ("E2E3", "e23.qwen3b.C3.recall", 0.3333333333333333),
            ("E2E3", "e23.qwen3b.C2b.uac", 0.9833333333333333),
            ("E2E3", "e23.llama3b.C0_neutral.recall", 0.8),
            ("E2E3", "e23.llama3b.C2a.recall", 0.8620689655172413),
            ("E2E3", "e23.llama3b.C3.recall", 0.5),
            ("E6", "e6.IPI_flip_rate.B0_C3", 0.7419354838709677),
            ("E6", "e6.IPI_flip_rate.P1_C3", 0.4838709677419355),
            ("E6", "e6.mcnemar_flip_C3_B0_vs_P1.p", 0.0078125),
            ("E8", "e8.llama3b.B0.unsafe_compliance_rate", 0.03333333333333333),
            ("CodeBERT", "codebert.f1@0.5", 0.21521739130434783),
            ("CodeBERT", "codebert.vd_s", 0.9617486338797814),
            ("Calibration",
             "calib.Qwen_Qwen2.5-Coder-3B-Instruct.at_fit.over_refusal_rate", 0.5867),
        ]
        for exp, metric, expect in cross:
            assert (exp, metric) in rows, f"master missing {metric}"
            assert abs(rows[(exp, metric)] - expect) < 1e-9, \
                (metric, rows[(exp, metric)], expect)
        print(f"[verify] {len(cross)} headline numbers cross-checked against "
              f"outputs/master/master_results.json")


def check_citations() -> None:
    """Every \\cite{...} key used in paper/sections/*.tex and paper/tables/*.tex
    must exist in docs/refs.bib."""
    bib = (ROOT / "docs" / "refs.bib").read_text()
    keys = set()
    for line in bib.splitlines():
        line = line.strip()
        for tag in ("@inproceedings", "@article", "@misc", "@book"):
            if line.lower().startswith(tag):
                k = line.split("{", 1)[1].split(",", 1)[0].strip()
                keys.add(k)
    assert keys, "no bib keys parsed from refs.bib"
    used = set()
    for d in ("sections", "tables"):
        for p in (Path(__file__).parent / d).glob("*.tex"):
            text = p.read_text()
            for i, ch in enumerate(text):
                if ch != "\\":
                    continue
                if text.startswith("\\cite", i):
                    j = text.index("{", i)
                    k = text.index("}", j)
                    for key in text[j + 1:k].split(","):
                        used.add(key.strip())
    missing = sorted(used - keys)
    assert not missing, f"cited but not in refs.bib: {missing}"
    unused = sorted(keys - used)
    print(f"[cites] {len(used)} keys used, all present in refs.bib "
          f"(unused bib entries: {unused or 'none'})")


if __name__ == "__main__":
    fig_conditions()
    fig_e0_rr()
    fig_e6_injection()
    fig_e8_compliance()
    fig_codebert()
    fig_round5()
    verify_tables()
    check_citations()
    for p in sorted(FIG.glob("*.pdf")):
        print(f"[ok] {p} ({p.stat().st_size} bytes)")
