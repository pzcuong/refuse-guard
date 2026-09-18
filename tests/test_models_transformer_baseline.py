"""Tests for Round 2 transformer-baseline additions (owner: A2).

Focus: head+tail id encoding (`_encode_ids` / `_pad_batch` / `_encode`
delegation), config defaults (pos_weight / scheduler / ckpt cadence), and the
NaN fail-fast contract. GPU work is NOT exercised here (tests must stay fast
and CI-safe); the MPS training loop is verified by scripts/train_codebert.py.
"""
from __future__ import annotations

import pytest

from src.models.transformer_baseline import DEFAULT_CFG, TransformerBaseline


# --------------------------------------------------------------------- config
def test_default_cfg_has_round2_fields():
    for key in ("scheduler", "dtype", "pos_weight", "ckpt_every_steps",
                "speed_test_steps", "allow_random_head"):
        assert key in DEFAULT_CFG
    assert DEFAULT_CFG["max_seq_len"] == 512
    assert DEFAULT_CFG["scheduler"] == "cosine"
    assert DEFAULT_CFG["pos_weight"] == "auto"


def test_predict_without_checkpoint_raises(tmp_path):
    """A random-head silent evaluation must be impossible (round-1 LOW fix)."""
    tb = TransformerBaseline(cfg={
        "output_dir": str(tmp_path / "no_ckpt"), "device": "cpu"})
    with pytest.raises(FileNotFoundError):
        tb.predict(["int main(){return 0;}"])


# --------------------------------------------------------------- tokenization
@pytest.fixture(scope="module")
def cpu_tb():
    tb = TransformerBaseline(cfg={"device": "cpu"})
    tb._lazy_load(seq_len=512)  # downloads/loads tokenizer+model (cached in CI image)
    return tb


def test_encode_ids_short(cpu_tb):
    tok = cpu_tb.tokenizer
    ids = cpu_tb._encode_ids("int main(){return 0;}")
    assert ids[0] == tok.cls_token_id and ids[-1] == tok.sep_token_id
    assert len(ids) <= 512


def test_encode_ids_overlong_head_tail(cpu_tb):
    """Over-long inputs must keep the head AND tail of the FULL-text token
    stream under a 512 budget, wrapped in [CLS] ... [SEP] ... [SEP]."""
    tok = cpu_tb.tokenizer
    body = "x = 1;\n" * 3000  # way over 512 tokens
    ids = cpu_tb._encode_ids(body)
    assert len(ids) <= 512
    assert ids[0] == tok.cls_token_id and ids[-1] == tok.sep_token_id
    assert tok.sep_token_id in ids[1:-1]  # explicit mid-[SEP] between halves
    full_ids = tok(body, add_special_tokens=False)["input_ids"]
    keep = 512 - 3
    head_ids, tail_ids = full_ids[: keep // 2], full_ids[len(full_ids) - (keep - keep // 2):]
    assert len(head_ids) == 254 and len(tail_ids) == 255  # 509 split 254/255
    # decode-compare: the head block and tail block are preserved verbatim
    assert tok.decode(ids[1:1 + len(head_ids)]) == tok.decode(head_ids)
    assert ids[1 + len(head_ids)] == tok.sep_token_id          # mid-[SEP]
    assert tok.decode(ids[2 + len(head_ids): len(ids) - 1]) == tok.decode(tail_ids)


def test_encode_delegation_identical_to_pad_batch(cpu_tb):
    texts = ["short fn", "y" * 4000]
    enc = cpu_tb._encode(texts)
    rows = [cpu_tb._encode_ids(t) for t in texts]
    enc2 = cpu_tb._pad_batch(rows)
    assert (enc["input_ids"] == enc2["input_ids"]).all()
    assert (enc["attention_mask"] == enc2["attention_mask"]).all()


def test_pad_batch_right_pads_with_mask(cpu_tb):
    tok = cpu_tb.tokenizer
    r1 = [tok.cls_token_id] + [5] * 10 + [tok.sep_token_id]
    r2 = [tok.cls_token_id] + [6] * 3 + [tok.sep_token_id]
    enc = cpu_tb._pad_batch([r1, r2])
    assert enc["input_ids"].shape == (2, 12)
    assert enc["attention_mask"][0].tolist() == [1] * 12
    assert enc["attention_mask"][1].tolist() == [1] * 5 + [0] * 7


# ---------------------------------------------------------------------------
# Round 3: eval-script helpers (scripts/eval_codebert.py), imported by path
# (scripts/ is not a package). Pure functions, no GPU / no data loading.
# ---------------------------------------------------------------------------
import importlib.util as _ilu
from pathlib import Path

_EVAL_PATH = Path(__file__).resolve().parents[1] / "scripts" / "eval_codebert.py"
_spec = _ilu.spec_from_file_location("eval_codebert_mod", _EVAL_PATH)
eval_codebert = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(eval_codebert)


class TestClassificationMetrics:
    def test_perfect_separation(self):
        m = eval_codebert._classification_metrics([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9])
        assert m["recall@0.5"] == 1.0
        assert m["f1@0.5"] == 1.0
        assert m["mcc@0.5"] == 1.0
        assert m["auc"] == 1.0
        assert m["accuracy@0.5"] == 1.0
        assert m["vd_s"] == 0.0  # FNR=0 at an FPR<=0.5% operating point
        assert m["n_vulnerable"] == 2 and m["n_benign"] == 2

    def test_all_benign_at_05_but_inverted_ranking(self):
        # wrong at 0.5 AND a vulnerable scoring BELOW a benign: the FPR<=0.5%
        # operating point must sit above the top benign score, so every
        # vulnerable function is missed -> VD-S (FNR) = 1.0.
        m = eval_codebert._classification_metrics([0, 1, 1], [0.8, 0.3, 0.4])
        assert m["recall@0.5"] == 0.0
        assert m["f1@0.5"] == 0.0
        assert m["vd_s"] == 1.0

    def test_vd_s_is_threshold_free_perfect_rank(self):
        # all-benign predictions at 0.5 yet perfectly ranked scores: VD-S is
        # threshold-free, so the FPR-constrained point still recovers FNR=0.
        m = eval_codebert._classification_metrics([0, 1, 1], [0.2, 0.3, 0.4])
        assert m["recall@0.5"] == 0.0
        assert m["vd_s"] == 0.0

    def test_single_class_returns_none_not_crash(self):
        m = eval_codebert._classification_metrics([1, 1], [0.2, 0.9])
        assert m["mcc@0.5"] is None and m["auc"] is None and m["vd_s"] is None


class TestPairedMetrics:
    def test_perfect_ranking_both_correct(self):
        out = eval_codebert._paired_metrics([0.9, 0.8], [0.1, 0.2], threshold=0.6)
        assert out["n_pairs"] == 2
        assert out["p_c_both_correct@0.5"] == 1.0
        assert out["p_v_both_vulnerable@0.5"] == 0.0
        assert out["p_b_both_benign@0.5"] == 0.0
        assert out["p_r_inverse@0.5"] == 0.0
        assert out["paired_rank_accuracy"] == 1.0
        assert out["paired_detection_score@thr"] == 1.0

    def test_inverse_predictions(self):
        out = eval_codebert._paired_metrics([0.1], [0.9], threshold=0.5)
        assert out["p_r_inverse@0.5"] == 1.0
        assert out["paired_rank_accuracy"] == 0.0

    def test_empty_pairs(self):
        out = eval_codebert._paired_metrics([], [], threshold=0.5)
        assert out["n_pairs"] == 0 and out["p_c_both_correct@0.5"] is None
