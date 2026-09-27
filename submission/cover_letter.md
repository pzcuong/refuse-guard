# Cover Letter — Paper 2 (PackGuard) → Computers & Security

> DRAFT cho W2/orchestrator review. Venue #1 theo `submission/venue_fit.md`.
> Nguyên tắc: không superlative, không "first/novel" chưa có hedge, mọi số
> trùng khớp `submission/PackGuard_ms.pdf` (8 trang) và artifact truy vết
> trong `% SRC` comments. Điền tên/đơn vị khi bỏ anonymous.

---

Dear Editors of *Computers & Security*,

We submit our manuscript **"The Advisory Inside: Measuring and Closing an
In-Package Attack Surface on LLM Package Analyzers"** for consideration as
a research paper.

Large language models are increasingly used to screen open-source packages
for malicious behavior, and the files such a model reads are written by the
attacker. Prior work on LLM safety under adversarial pressure studied
prompt-level interference; our manuscript measures a channel those designs
do not express: untrusted content *inside* the analyzed package file, where
a planted advisory-style security comment is, at the input layer,
indistinguishable from the reviewer's own note.

Three findings, each pre-registered and measured over real npm/PyPI
packages:

1. **The attack is recall-perturbing and family-dependent.** A single
   inert advisory comment shifts verdict sensitivity on genuinely malicious
   packages in opposite directions per model family: malicious recall
   rises .667→.833 for granite-3.3-2B but falls .167→.042 for
   Llama-3.2-3B in the paired measurement. At measurement scale n=100, the
   inflated family additionally starts flagging benign packages (benign
   false positives 0→2/100). Both directions harm a scanner. Refusals are
   absent throughout (RR=0 across 2,700 defensive-task generations at
   2–3B), so the widely reported defensive-refusal bias does not transfer
   to this domain at these scales — a boundary condition, stated as such.

2. **A simple defense closes the channel — at a measured, family-dependent
   price.** Stripping comments/docstrings behind an AST re-parse
   equivalence gate provably removes the advisory (stripped attack file
   byte-identical to the stripped original on all 38 gated samples) and
   fully neutralizes it on the model it inflates: every parseable defended
   verdict matches the no-attack baseline (23/23), all four
   advisory-induced changes revert, benign false positives stay zero. On
   Llama-3.2-3B the same strip restores nothing — the lost detections are
   byte-identical snippets of a single package family whose own comments
   the defense also removes. We report this cost as a first-class outcome,
   not an aggregate footnote.

3. **The detector beneath the measurements is federation-robust.** The
   behavior-graph classifier trained federated over ecosystem partitions is
   statistically equivalent to a strong centralized baseline
   (pre-registered TOST at ±.02 F1: ΔF1 −.0065, 90% CI [−.0133, +.0003])
   and adds a significant margin over a trivial structural baseline
   (+.0227/+.0487 F1, exact Wilcoxon p ≤ 1.9e-5). A leave-cluster-out
   evaluation of family shift yields a null with quantified power
   (p = .368), which we report two-directionally: no robustness ranking
   between feature representations is supported, and none is claimed. A
   pre-registered GuardDog rule-based baseline is *comparable, not
   superior* (and optimistically biased by shared data origin — disclosed).

**Scope and honesty statements.** All conclusions close at 2–3B open-weight
model scale, two ecosystems (npm, PyPI), and a pilot corpus of 603
provenance-tracked packages (390 malicious from a wild-capture dataset,
213 popularity-derived benign); federated trust mechanisms are simulations,
disclosed as such. Negative results are reported in the main text: the
family-shift null above, a mechanism ablation that is a null with low
power, and a knowledge-base augmentation that leaves accuracy essentially
neutral. Every number traces to released artifacts via a generated-macro
pipeline, and the manuscript condenses its own audit history (retractions
and metric-semantics corrections) in a Threats-to-Validity section and an
appendix.

We believe the manuscript fits *Computers & Security*'s scope at the
intersection of software supply-chain security and AI security measurement:
it measures a concrete attack surface on an emerging class of security
analyzers, demonstrates and prices a practical defense, and documents the
conditions under which both hold. The manuscript is under double-blind
review (8 pages, ACM format; we will reformat to the journal template on
request). It is not under consideration elsewhere; a companion
vulnerability-domain measurement study is cited as prior work and will not
be submitted to this journal concurrently.

Suggested reviewers / conflicts: none declared.

Sincerely,
The Authors (anonymous for review)

---

## Checklist nội bộ (không gửi đi)
- [x] 3 findings trùng số với PDF (granite .667→.833 / llama .167→.042;
      23/23, 4/4, 38/38; TOST −.0065 CI [−.0133,+.0003]; trivial
      +.0227/+.0487 p≤1.9e-5; LCO p=.368; GuardDog comparable).
- [x] Pilot scope 603 / 2 ecosystems / 2–3B / simulation disclosure.
- [x] Negative results: LCO null, mechanism null-low-power, KB neutral,
      GuardDog comparable — đều được nêu.
- [x] Không superlative ("first" chỉ xuất hiện dạng hedged trong bài,
      cover letter dùng "does not transfer ... at these scales").
- [ ] Điền thông tin liên hệ khi bỏ anonymous; kiểm tra chính sách
      concurrent submission của venue đích tại thời điểm nộp.
