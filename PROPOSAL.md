ĐỀ XUẤT
PHÁT HIỆN LỖ HỔNG PHẦN MỀM BẰNG LLM BỀN VỮNG TRƯỚC SAFETY-INDUCED BLOCKING VÀ NGỮ CẢNH MÃ NGUỒN KHÔNG TIN CẬY
Robust LLM-Based Software Vulnerability Detection under
Safety-Induced Blocking and Untrusted Code Context
Định hướng nghiên cứu
•	Bài toán trung tâm: phát hiện lỗ hổng phần mềm bằng LLM trong bối cảnh safety alignment có thể gây từ chối sai hoặc suy giảm tính hữu dụng đối với các tác vụ phòng thủ hợp lệ.
•	Đóng góp dự kiến: benchmark clean/contextualized trên PrimeVul; đánh giá refusal và utility; cơ chế Semantic Context Isolation; Refusal Monitor; Transformer fallback; đánh giá đồng thời defensive utility và safety preservation.
•	Nguyên tắc khoa học: không giả định rằng chỉ cần chèn một đoạn nội dung nhạy cảm là LLM sẽ từ chối. Giai đoạn đầu bắt buộc tái lập hiện tượng theo literature trước khi khẳng định threat model.
Tháng 09 năm 2026
 
TÓM TẮT ĐỀ XUẤT
Các mô hình ngôn ngữ lớn (Large Language Models - LLMs) ngày càng được sử dụng trong code review, vulnerability triage, CWE attribution, localization và hỗ trợ sửa lỗi. Tuy nhiên, các tác vụ phòng thủ hợp lệ thường sử dụng cùng thuật ngữ và mô tả kỹ thuật xuất hiện trong ngữ cảnh tấn công. Nghiên cứu gần đây về Defensive Refusal Bias cho thấy safety-aligned LLMs có thể từ chối các yêu cầu phòng thủ chứa thuật ngữ an ninh nhạy cảm với tần suất cao hơn các yêu cầu trung tính tương đương [1]. OR-Bench và XSTest cũng cho thấy over-refusal là một failure mode có thể đo lường một cách hệ thống [2], [3].
Trong software vulnerability analysis, vấn đề không dừng ở một câu trả lời “I cannot assist”. Một hệ thống có thể vẫn trả lời nhưng bỏ sót lỗ hổng, sai CWE, localization không chính xác hoặc cung cấp đầu ra không đủ khả năng sử dụng. Nghiên cứu Beyond Refusal (2026) nhấn mạnh rằng safety state có thể làm thay đổi utility profile của vulnerability analysis ngay cả khi outright refusal không phải failure mode chi phối [4]. Đồng thời, source code và repository chứa các thành phần model-facing không đáng tin cậy như comment, string literal, documentation và metadata; các công trình về indirect prompt injection trong code context cho thấy đây là một attack surface thực tế [5], [6].
Luận văn đề xuất RefuseGuard, một framework phát hiện lỗ hổng kết hợp: (i) task-intent gate để cố định mục tiêu phòng thủ; (ii) semantic context isolation nhằm tách nguồn gốc và vai trò của các thành phần văn bản trong code mà không xóa mù quáng thông tin có ý nghĩa bảo mật; (iii) LLM analyzer cho detection/CWE/localization; (iv) refusal monitor để phân biệt answer, partial answer và refusal; và (v) Transformer-based vulnerability detector đóng vai trò independent prior/fallback. Dataset chính dự kiến là PrimeVul, một benchmark C/C++ thực tế với khoảng 7 nghìn hàm vulnerable và 229 nghìn hàm benign, bao phủ hơn 140 CWE và có paired vulnerable-patched samples [7].
Điểm then chốt của thiết kế nghiên cứu là một reproduction gate: luận văn không giả định trước rằng safety-sensitive text trong source code sẽ luôn gây refusal. Giai đoạn pilot trước tiên tái lập các hiệu ứng đã được báo cáo ở mức distribution/model/prompt setting. Nếu safety-induced refusal đủ mạnh, luận văn tập trung vào false-refusal mitigation; nếu không, scope vẫn giữ giá trị dưới bài toán rộng hơn: robust vulnerability analysis dưới untrusted code context và indirect prompt injection. Cách đặt vấn đề này giúp tránh phụ thuộc vào một trigger đặc thù và tạo một thesis có thể bảo vệ được bằng thực nghiệm.
Hạng mục	Thiết kế đề xuất
Bài toán	Vulnerability detection / analysis trong LLM
Dataset chính	PrimeVul; tùy chọn external validation: DiverseVul/BigVul
LLM output	Vulnerable/benign, CWE, location, root cause, usable-answer status
Transformer	CodeBERT/GraphCodeBERT hoặc mô hình tương đương làm baseline + fallback
Hiện tượng nghiên cứu	Defensive refusal bias, over-refusal, utility degradation, untrusted code context
Defense chính	Task-intent gate + semantic context isolation + refusal recovery + Transformer fallback
Metric chính	Vulnerability Recall/F1/MCC, refusal rate, usable-answer coverage, clean utility loss, safety preservation

1. ĐẶT VẤN ĐỀ VÀ LÝ DO CHỌN ĐỀ TÀI
Phát hiện lỗ hổng từ mã nguồn là bài toán khó vì tín hiệu phân biệt thường nhỏ, phụ thuộc ngữ cảnh và dễ bị che khuất bởi dữ liệu không cân bằng. PrimeVul cho thấy các benchmark cũ có thể đánh giá quá lạc quan code language models; trong thiết lập nghiêm ngặt, hiệu năng giảm mạnh, nhấn mạnh khoảng cách giữa benchmark và triển khai thực tế [7]. Vì vậy, một vulnerability scanner dựa trên LLM không chỉ cần đúng trên clean code mà còn phải ổn định trước các biến thiên context thực tế.
Ở lớp LLM, safety alignment tạo ra một tension đặc thù cho cybersecurity: cùng các thuật ngữ “exploit”, “payload”, “shell”, “malware”, “bypass” có thể xuất hiện trong cả yêu cầu tấn công và yêu cầu phòng thủ hợp pháp. Defensive Refusal Bias báo cáo mức từ chối của các yêu cầu cyber-defense chứa security-sensitive wording cao gấp 2,72 lần các phiên bản neutral tương đương trên 2.390 tác vụ NCCDC [1]. Điều này cho thấy refusal policy có thể phản ứng với surface semantics thay vì chỉ dựa trên intent.
Ngoài user prompt, source code/repository cũng là một kênh context không đáng tin cậy. BIPIA chỉ ra rằng LLM khó phân biệt informational context và actionable instructions trong external content [6]. CodeSentinel tiếp tục chỉ ra code comments, strings, identifiers và decoy code là các model-facing nodes có thể mang prompt-injection content [5]. TabooRAG (2026) cho thấy một lớp availability/blocking attack khác: query-relevant risk context có thể khai thác safety alignment để gây refusal trong RAG [8]. Tuy nhiên, việc chuyển các quan sát này sang vulnerability analysis cần được kiểm chứng thay vì mặc định đúng.
Khoảng trống luận văn vì thế không nên được mô tả đơn giản là “chèn câu vi phạm vào comment để làm LLM từ chối”. Câu hỏi có giá trị hơn là: làm thế nào duy trì defensive utility của vulnerability analyzer khi safety alignment và untrusted code context tương tác, mà không vô hiệu hóa safety? Đây là bài toán vừa có relevance về software security vừa có chiều sâu về trustworthy LLM.
2. MỤC TIÊU NGHIÊN CỨU
2.1. Mục tiêu tổng quát
Xây dựng và đánh giá một framework phát hiện lỗ hổng phần mềm dựa trên LLM có khả năng giảm false refusal và utility degradation trong các ngữ cảnh an ninh nhạy cảm, đồng thời duy trì safety đối với các yêu cầu thực sự không phù hợp. Framework sử dụng Transformer-based vulnerability detector như một kênh phân tích độc lập và fallback khi LLM không cung cấp đầu ra sử dụng được.
2.2. Mục tiêu cụ thể
•	Tái lập có kiểm soát Defensive Refusal Bias / over-refusal trên các tác vụ vulnerability analysis trước khi xây defense.
•	Xây dựng baseline vulnerability detection trên PrimeVul bằng Transformer-based code model và nhiều LLM.
•	Thiết kế paired clean/contextualized evaluation set trong đó vulnerability label và program semantics được giữ nguyên.
•	Đo riêng outright refusal, partial refusal, usable-answer coverage, vulnerability correctness, CWE attribution và localization.
•	Đánh giá các baseline đơn giản như comment stripping, prompt reframing và raw-code analysis để tránh novelty giả.
•	Đề xuất Semantic Context Isolation nhằm giữ security-relevant semantics nhưng giảm ảnh hưởng của untrusted model-facing context.
•	Thiết kế Refusal Monitor và recovery policy, gồm structured retry và Transformer fallback.
•	Đánh giá safety-utility trade-off: giảm false refusal nhưng không làm tăng unsafe compliance.
3. CÂU HỎI NGHIÊN CỨU
Mã	Câu hỏi nghiên cứu
RQ1	Các LLM hiện đại có biểu hiện defensive refusal/utility degradation đáng kể trên vulnerability-analysis tasks hay không, và mức độ phụ thuộc model/prompt/context như thế nào?
RQ2	Security-sensitive wording và untrusted textual context ảnh hưởng đến vulnerability detection, CWE attribution và localization như thế nào so với clean condition?
RQ3	Simple defenses như comment stripping, raw sanitization hoặc prompt reframing giải quyết được bao nhiêu phần của vấn đề và gây clean-utility loss ra sao?
RQ4	Semantic Context Isolation có giảm refusal/utility degradation tốt hơn simple stripping trong khi bảo toàn security-relevant semantics hay không?
RQ5	Transformer-based vulnerability detector có thể cung cấp independent prior/fallback hiệu quả khi LLM trả partial/refusal hay không?
RQ6	RefuseGuard có cải thiện defensive utility dưới contextual stress mà vẫn duy trì safety preservation trên safe/unsafe contrast sets hay không?
RQ7	Defense có generalize qua model family, CWE group và dataset ngoài PrimeVul hay không?

4. GIẢ THUYẾT VÀ NGUYÊN TẮC KIỂM CHỨNG
Mã	Giả thuyết
H1	Một số model/setting sẽ có refusal hoặc utility drop cao hơn đáng kể khi task/context chứa security-sensitive cues, nhưng hiệu ứng không được giả định là universal.
H2	Outright refusal chỉ là một phần failure mode; partial answer, wrong CWE và failed localization có thể chiếm tỷ trọng lớn.
H3	Comment stripping xử lý tốt comment-only carrier nhưng không phải defense tổng quát khi textual artifacts mang security semantics.
H4	Semantic Context Isolation giảm contextual sensitivity với clean-utility loss nhỏ hơn aggressive text removal.
H5	Refusal-aware Transformer fallback làm tăng usable vulnerability coverage mà không cần ablate safety alignment của LLM.
H6	Một defense tốt phải đồng thời giảm false refusal và giữ unsafe-compliance rate xấp xỉ baseline.

Reproduction gate: nếu E0 không tái lập được một hiệu ứng refusal/utility shift có ý nghĩa trên nhiều model/condition, luận văn không claim “safety-induced blocking attack” như hiện tượng phổ quát. Khi đó RQ2-RQ7 được tái diễn giải dưới scope rộng hơn: robustness của LLM vulnerability analysis trước untrusted context / indirect prompt injection. Đây là cơ chế bảo vệ validity của luận văn.
5. PHẠM VI VÀ DỮ LIỆU NGHIÊN CỨU
5.1. Phạm vi
•	Ngôn ngữ chính: C/C++ để tận dụng PrimeVul và các code-model baseline đã được dùng phổ biến.
•	Đơn vị phân tích chính: function-level vulnerability detection; localization/CWE được đánh giá trên subset có ground truth phù hợp.
•	Không đặt mục tiêu xây sandbox malware, exploit-generation system hoặc autonomous offensive agent.
•	Không thay đổi trọng số safety của proprietary LLM; defense ưu tiên inference-time mediation và fallback.
•	Đánh giá cả API-based LLM và ít nhất một open-weight model nếu tài nguyên cho phép.
5.2. Dataset chính: PrimeVul
PrimeVul được thiết kế cho realistic vulnerability detection, với khoảng 7.000 vulnerable functions và 229.000 benign functions từ các dự án C/C++, bao phủ hơn 140 CWE; benchmark sử dụng deduplication, chronological split và paired vulnerable/patched samples để giảm data leakage và đánh giá phân biệt các biến đổi nhỏ [7]. Luận văn sử dụng official split và tránh tự fit preprocessing trên test.
Do chi phí LLM, evaluation set có thể được tạo từ test split theo stratified sampling: ưu tiên toàn bộ vulnerable samples trong ngân sách, matched benign samples và paired vulnerable/patched cases. Kích thước cuối cùng được xác định sau pilot cost analysis; sampling seed và sample IDs phải được công bố để tái lập.
5.3. Context / refusal corpora
OR-Bench cung cấp 80.000 over-refusal prompts, hard subset khoảng 1.000 và 600 toxic prompts; XSTest có 250 safe prompts và 200 unsafe contrasts [2], [3]. Luận văn không ghép trực tiếp các prompt này vào code một cách ngẫu nhiên. Chúng được dùng để xây taxonomy của safety-sensitive wording, calibration/evaluation of refusal detector, và safety-preservation contrast. BIPIA cung cấp benchmark indirect prompt injection với một CodeQA task, hữu ích làm external robustness reference [6].
6. THREAT MODEL VÀ ĐIỀU KIỆN THỰC NGHIỆM
Luận văn xem source/repository context là dữ liệu không đáng tin cậy đối với LLM. Adversary hoặc artifact producer có thể kiểm soát comment, documentation, metadata và một số textual fields; nhưng không kiểm soát system prompt, model weights hoặc ground-truth vulnerability label. Mục tiêu quan sát là làm giảm availability/utility của defensive analysis: refusal, partial response, vulnerability omission hoặc sai localization. Đây là threat model cho robustness evaluation; không giả định mọi contextual transformation đều là “attack” thành công.
Condition	Mô tả	Mục tiêu
C0 - Clean	Code gốc, standardized defensive prompt.	Baseline utility/refusal.
C1 - Defensive wording	Cùng code, prompt/task wording có security-sensitive terminology nhưng giữ intent phòng thủ.	Reproduce Defensive Refusal Bias.
C2 - Benign contextual stress	Thêm model-facing context nhạy cảm nhưng không thay đổi program semantics và không chứa instruction tấn công.	Measure contextual over-refusal / degradation.
C3 - IPI extension	Instruction-like untrusted repository context theo benchmark/attack families hiện có.	Đánh giá robustness rộng hơn; không phải core refusal hypothesis.
C4 - Defense	C1-C3 qua comment strip / semantic isolation / RefuseGuard.	So sánh recovery và clean utility loss.

 
Hình 1. Kiến trúc tổng quan RefuseGuard.
7. PHƯƠNG PHÁP ĐỀ XUẤT: REFUSEGUARD
7.1. Task-Intent Gate
Mục tiêu là cố định task trước khi raw code/context đi vào analyzer. Gate chỉ xác định loại yêu cầu ở mức coarse-grained: defensive vulnerability analysis, ambiguous, hoặc ngoài phạm vi. Với defensive task, output schema được khóa ở vulnerable/benign, CWE, location, root cause và confidence. Context nằm trong source code không được phép tự động thay đổi task classification.
7.2. Parser và Context Provenance
Sử dụng Tree-sitter hoặc parser tương đương để tách executable syntax, comments, string literals, identifiers, docstrings/config-like nodes và structural information. Mỗi node được gắn provenance/type thay vì coi toàn bộ file là một text stream đồng nhất. Ý tưởng này liên quan đến code-context defenses như CodeSentinel, nhưng luận văn tập trung vào preserving vulnerability-analysis utility và refusal-aware recovery [5].
7.3. Semantic Context Isolation
Không xóa toàn bộ natural-language content. Với comment-only carrier, comment stripping được coi là baseline hợp lệ. Với string/query/path/format text có khả năng mang security semantics, hệ thống ưu tiên abstraction hoặc structured representation. Ví dụ, thay vì đưa raw command string như một instruction-like sequence, mediator có thể biểu diễn data-flow: USER_INPUT → concatenation → system(argument). Mục tiêu là giữ bằng chứng vulnerability nhưng giảm khả năng model diễn giải artifact text như task-level instruction.
7.4. LLM Analyzer
LLM nhận standardized prompt và structured code representation. Đầu ra bắt buộc theo schema: analysis_status, vulnerable, CWE, location, root_cause, confidence. Việc chuẩn hóa output giúp phân biệt refusal với prediction benign và giảm ambiguity khi tính metric.
7.5. Transformer Detector và Fallback
CodeBERT/GraphCodeBERT hoặc một code Transformer tương đương được fine-tune trên PrimeVul để tạo vulnerability prior độc lập. Transformer classifier không có instruction-following refusal state giống chat LLM, nên vừa là control group để tách representation shift khỏi safety behavior, vừa là fallback khi LLM không trả kết quả sử dụng được. Fusion chỉ được kích hoạt theo policy định trước; không tối ưu trên test set.
7.6. Refusal Monitor và Recovery
Monitor phân loại output thành ANSWER, PARTIAL hoặc REFUSAL dựa trên schema completeness và một refusal detector được kiểm chứng bằng corpus calibration. Nếu refusal/partial xảy ra, hệ thống lần lượt thử structured retry trên context đã mediated và, nếu vẫn thất bại, dùng Transformer fallback. Nguyên tắc là refusal không được ánh xạ thành “benign”.
8. BASELINE VÀ THIẾT KẾ THỰC NGHIỆM
8.1. Baselines
ID	Phương pháp	Vai trò
B0	Raw LLM	Source code + standardized prompt, không defense.
B1	Prompt Reframing	Nêu rõ defensive intent/authorization nhưng không thay code context.
B2	Comment Strip	Loại comments trước khi đưa code vào LLM; bắt buộc để trả lời objection “just remove comments”.
B3	Aggressive Text Removal	Loại/ẩn phần lớn textual nodes; dùng để đo clean utility loss.
B4	Transformer-only	CodeBERT/GraphCodeBERT vulnerability classifier.
P1	Semantic Isolation	Parser + provenance + semantic-preserving mediation.
P2	RefuseGuard	P1 + LLM + refusal monitor + structured retry + Transformer fallback.

8.2. Ma trận thực nghiệm
ID	Thực nghiệm	Mô tả	RQ
E0	Reproduction gate	Tái lập refusal/utility shift theo settings từ literature trên >=3 model/conditions.	RQ1
E1	Clean baseline	LLM và Transformer trên PrimeVul clean split.	RQ1
E2	Prompt-framing sensitivity	Neutral vs security-sensitive defensive wording.	RQ1,RQ2
E3	Contextual stress	Clean vs semantics-preserving contextual variants.	RQ2
E4	Carrier/position ablation	Comment, header, string-like/metadata; near/far vị trí khi hợp lệ.	RQ2,RQ3
E5	Simple defense	Comment strip / aggressive removal / reframing.	RQ3
E6	Semantic isolation	Đánh giá proposed mediator.	RQ4
E7	Refusal recovery	Retry + Transformer fallback + fusion ablation.	RQ5,RQ6
E8	Safety preservation	Safe/unsafe contrast để kiểm tra defense không làm tăng harmful compliance.	RQ6
E9	Cross-model / external data	Generalization qua model family và dataset thứ hai nếu tiến độ cho phép.	RQ7

 
Hình 2. Protocol thực nghiệm và reproduction gate của luận văn.
9. TIÊU CHÍ ĐÁNH GIÁ VÀ PHÂN TÍCH THỐNG KÊ
Metric	Ý nghĩa
Vulnerability Recall / F1 / MCC	Hiệu năng phát hiện; Recall đặc biệt quan trọng vì false negative có chi phí cao.
PrimeVul VD-Score / paired metrics	Dùng metric/evaluation guideline của PrimeVul khi phù hợp để tránh chỉ báo cáo accuracy/F1.
Refusal Rate (RR)	Tỷ lệ output bị phân loại REFUSAL.
Partial Answer Rate	Tỷ lệ có trả lời nhưng thiếu prediction/CWE/location theo schema.
Usable Answer Coverage (UAC)	Tỷ lệ mẫu tạo được đầu ra đủ để dùng cho vulnerability triage.
Safety-Induced Utility Drop (SIUD)	U_clean - U_context; có thể tính riêng cho Recall, UAC hoặc composite utility.
Defense Recovery Rate (DRR)	Tỷ lệ sample từ refusal/partial ở baseline được phục hồi thành usable correct answer sau defense.
Clean Utility Loss (CUL)	Utility_raw,clean - Utility_defense,clean; defense tốt phải giữ CUL nhỏ.
Unsafe Compliance Rate	Safety-preservation metric trên unsafe contrast set; không được tăng đáng kể so với baseline.

Các so sánh clean/contextualized phải dùng paired statistics. Tùy metric, sử dụng McNemar test cho paired categorical outcomes, bootstrap confidence interval cho utility differences và báo effect size. Khi chạy nhiều prompt/model conditions, cần kiểm soát multiple comparisons hoặc xác định trước primary endpoint để tránh cherry-picking.
10. ĐÓNG GÓP DỰ KIẾN
C1 - Vulnerability-specific evaluation protocol: Một protocol tái lập, tách refusal, partial response và correctness thay vì gộp tất cả thành accuracy.
C2 - Paired contextual benchmark: Clean/contextualized pairs trên PrimeVul với program semantics và vulnerability label được giữ nguyên; công bố transform metadata và sample IDs.
C3 - Semantic Context Isolation: Defense không dựa vào keyword blacklist hoặc xóa mù quáng comments/strings; bảo toàn security-relevant semantics bằng provenance và structured mediation.
C4 - Refusal-aware hybrid defense: Kết hợp LLM reasoning với Transformer prior/fallback để refusal không đồng nghĩa với no analysis.
C5 - Joint safety-utility evaluation: Đo đồng thời defensive utility và safety preservation; tránh “fix” over-refusal bằng cách làm model indiscriminately compliant.
11. ĐỊNH VỊ NOVELTY SO VỚI RELATED WORK
Related work	Đã giải quyết	Khoảng trống luận văn
Defensive Refusal Bias [1]	Đo refusal bias trên cyber-defense tasks.	Luận văn chuyển trọng tâm sang vulnerability analysis và xây inference-time defense có utility/safety evaluation.
OR-Bench / XSTest [2],[3]	Benchmark over-refusal nói chung.	Dùng làm calibration/contrast; không thay thế vulnerability benchmark.
Beyond Refusal [4]	Same-lineage study về safety state và vulnerability-analysis utility.	Luận văn không ablate safety; tập trung defense + context provenance + fallback.
CodeSentinel [5]	Defense indirect prompt injection trong code contexts bằng sanitizer.	Luận văn nhấn mạnh false refusal/utility, semantic preservation và refusal recovery.
BIPIA [6]	Benchmark + defense cho indirect prompt injection qua external content.	Là extension robustness baseline; thesis task là vulnerability detection.
TabooRAG [8]	Safety-alignment blocking trong RAG.	Cung cấp motivation cho availability risk; luận văn không giả định transfer sang code mà kiểm chứng bằng E0/E3.
PrimeVul [7]	Realistic vulnerability dataset/evaluation.	Là substrate cho clean/contextualized paired benchmark và Transformer baseline.

Claim novelty cuối cùng chỉ được chốt sau một systematic search trước khi viết paper. Proposal hiện chỉ xác định một khoảng trống có cơ sở: defense cho vulnerability-analysis utility dưới safety-induced refusal và untrusted code context, không claim “first” nếu chưa audit literature đầy đủ.
12. GIỚI HẠN, RỦI RO VÀ PHƯƠNG ÁN XỬ LÝ
Rủi ro	Ảnh hưởng	Cách xử lý
Không tái lập được refusal	Hiệu ứng có thể phụ thuộc model/version/system policy.	Dùng reproduction gate; pivot sang robust vulnerability analysis under untrusted context; refusal trở thành secondary outcome.
Comment stripping giải quyết attack đơn giản	Novelty yếu nếu chỉ comment-only.	Đưa comment stripping thành baseline; tập trung security-relevant textual nodes và semantic-preserving mediation.
Dataset/API cost	PrimeVul lớn, nhiều LLM tốn chi phí.	Official test split + stratified paired subset; pilot để ước lượng power/cost; open model cho large-scale ablation.
Output judging bias	LLM-as-a-judge có thể không ổn định.	Ưu tiên structured fields + ground truth; manual audit subset; multiple judges khi cần.
Safety degradation	Defense giảm refusal nhưng tăng harmful compliance.	Bắt buộc safety contrast evaluation; không dùng refusal ablation làm defense chính.
Model drift	API model có thể thay version/policy.	Ghi model ID/date/config; cache raw outputs; ưu tiên open-weight model cho reproducibility.
Semantic preservation	Một số string/context removal thay đổi thông tin bảo mật.	Parser/provenance; AST/compile/unit-test checks khi có thể; tách trivial carrier và semantic carrier.

13. KẾ HOẠCH TRIỂN KHAI DỰ KIẾN
Thời gian	Nội dung	Đầu ra
Tuần 1-2	Literature audit; reproduce Defensive Refusal Bias / over-refusal settings; chốt model và primary endpoint.	Reproduction report + go/no-go decision
Tuần 3	Chuẩn bị PrimeVul, official split, paired subset, output schema.	Dataset manifest + EDA
Tuần 4-5	Transformer baseline + clean LLM baseline.	E1 results
Tuần 6-7	Context-condition generator; semantic-preservation checks; E2-E4.	Context benchmark v1
Tuần 8	Simple-defense baselines: reframing, stripping, aggressive removal.	E5 results
Tuần 9-10	Implement Semantic Context Isolation + refusal monitor.	RefuseGuard v1
Tuần 11	Transformer fallback/fusion + ablations.	E6-E7 results
Tuần 12	Safety preservation + cross-model validation.	E8-E9 results
Tuần 13-14	Statistical analysis, error analysis, threat-to-validity.	Tables/figures/final results
Tuần 15-16	Viết luận văn, code release, demo, defense slides.	Thesis + artifact package

14. SẢN PHẨM VÀ KẾT QUẢ DỰ KIẾN
•	Bộ code tái lập experiment: dataset preparation, prompt/config management, model runner, refusal parser, metric scripts.
•	Manifest clean/contextualized benchmark trên PrimeVul và metadata của từng transformation.
•	Fine-tuned Transformer vulnerability baseline và checkpoint/config nếu giấy phép cho phép.
•	RefuseGuard prototype gồm parser/context provenance, semantic mediator, refusal monitor và fallback policy.
•	Bảng clean vs contextualized vs defense cho nhiều model với confidence interval và statistical tests.
•	Safety-preservation report để chứng minh defense không đơn giản “trả lời mọi thứ”.
•	Demo: nhập source code → vulnerability report; hiển thị LLM status, Transformer prior và recovery path.
•	Luận văn + manuscript tiềm năng cho hướng software engineering / AI security nếu kết quả đủ mạnh.
15. CẤU TRÚC DỰ KIẾN
Chương	Nội dung
Chương 1	Giới thiệu: vulnerability detection, LLM safety/utility tension, mục tiêu, RQ, threat model.
Chương 2	Cơ sở và related work: code LMs, PrimeVul, over-refusal, defensive refusal bias, indirect prompt injection, blocking attacks.
Chương 3	Dataset và reproduction study: PrimeVul, context taxonomy, model setup, E0-E4.
Chương 4	Phương pháp RefuseGuard: task-intent gate, context provenance, semantic isolation, refusal monitor, Transformer fallback.
Chương 5	Thực nghiệm và kết quả: baselines, ablations, safety-utility trade-off, cross-model analysis.
Chương 6	Discussion: failure cases, limitations, external validity, implications cho LLM-based code security.
Chương 7	Kết luận và hướng phát triển: repository-level agent, multilingual code, learned mediator, formal safety/utility objectives.

16. KẾT LUẬN ĐỀ XUẤT
Đề tài được thiết kế để giải quyết một vấn đề thực tế nhưng tránh phụ thuộc vào một anecdotal trigger. Literature hiện tại cung cấp bằng chứng rằng over-refusal và defensive refusal bias tồn tại, rằng safety state ảnh hưởng vulnerability-analysis utility, và rằng untrusted code context là attack surface cho Code LLMs [1]-[6]. Tuy nhiên, mức độ các hiện tượng này tương tác trong vulnerability detection và defense nào giữ được cả defensive utility lẫn safety vẫn cần được kiểm chứng.
So với proposal malware-classification ban đầu, thesis mới chuyển task trung tâm sang vulnerability detection. Transformer không còn là “mô hình chính vì Transformer hiện đại”, mà có vai trò rõ về khoa học: control group để phân biệt representation robustness với instruction/safety behavior, và fallback độc lập khi LLM không cung cấp output dùng được. Nhờ vậy câu chuyện nghiên cứu thống nhất hơn: realistic vulnerability detection → safety/context failure modes → semantic-preserving defense → safety-utility evaluation.
Nếu reproduction gate cho kết quả dương, thesis có thể nhấn mạnh safety-induced blocking/refusal mitigation. Nếu kết quả âm, thesis vẫn không sụp đổ: contribution chuyển sang robust LLM vulnerability analysis under untrusted code context, với refusal chỉ là một secondary failure mode. Đây là framing phù hợp cho luận văn vì vừa có giả thuyết rõ, vừa có kế hoạch falsification và đường lui khoa học hợp lý.
TÀI LIỆU THAM KHẢO
[1] D. Campbell et al., “Defensive Refusal Bias: How Safety Alignment Fails Cyber Defenders,” ICLR 2026 Workshop on Agents in the Wild, 2026. arXiv:2603.01246.
[2] J. Cui, W.-L. Chiang, I. Stoica, and C.-J. Hsieh, “OR-Bench: An Over-Refusal Benchmark for Large Language Models,” ICML 2025, PMLR 267, pp. 11515-11542, 2025.
[3] P. Röttger, H. R. Kirk, B. Vidgen, G. Attanasio, F. Bianchi, and D. Hovy, “XSTest: A Test Suite for Identifying Exaggerated Safety Behaviours in Large Language Models,” arXiv:2308.01263, 2023.
[4] M. Li et al., “Beyond Refusal: A Same-Lineage Study of Aligned and Abliterated LLMs for Vulnerability Analysis,” arXiv:2607.05842, 2026.
[5] P.-H. Cheng, C.-M. Yu, Y.-D. Lin, Y.-S. Wu, and W.-B. Lee, “CodeSentinel: A Three-Layer Defense Against Indirect Prompt Injection in Code Contexts,” arXiv:2606.19235, 2026.
[6] J. Yi, Y. Xie, B. Zhu, E. Kiciman, G. Sun, X. Xie, and F. Wu, “Benchmarking and Defending Against Indirect Prompt Injection Attacks on Large Language Models,” arXiv:2312.14197, 2023.
[7] Y. Ding et al., “Vulnerability Detection with Code Language Models: How Far Are We?” 47th IEEE/ACM International Conference on Software Engineering (ICSE), 2025, DOI: 10.1109/ICSE55347.2025.00038. (PrimeVul).
[8] J. Li et al., “When Safety Becomes a Vulnerability: Exploiting LLM Alignment Homogeneity for Transferable Blocking in RAG,” arXiv:2603.03919, 2026.

