# Verification record

This is the retained **legacy standalone model** record. The current three-source integration, sample-training and complete test-suite results are in `THREE_INPUT_VERIFICATION.md`.

Executed 24 October 2026. This records software checks, not production validation.

## Environment

- Python 3.12.14
- NumPy 2.3.5; pandas 2.2.3; SciPy 1.17.0
- scikit-learn 1.8.0; joblib 1.5.3; threadpoolctl 3.6.0

## Executed checks

| Check | Result |
| --- | --- |
| Standard-library test suite | 46 tests passed |
| Three Model 1 candidates fit and compared | Passed |
| Calibration, threshold selection and untouched grouped test | Executed on synthetic fixtures only |
| Model 2 grouped out-of-fold scenario inputs and multi-label fitting | Executed on synthetic fixtures only |
| Shadow inference and rules/catalogue primary output | Passed |
| Synthetic release/promotion blocked | Passed |
| Artifact checksum/version checks before loading | Passed |
| Sensor failure, unknown category and sessionizer mismatch | Fail-closed behavior passed |
| Truth/raw-IP feature rejection and independent-run counting | Passed |
| Representative raw Wazuh/EVE parsing, deduplication, hash checks | Local fixtures passed |
| Bridge output validated by actual v0.3 Assessment/ControlRecommendation schemas | Passed using supplied source schemas and local shaped contexts |
| Full original-engine API/dashboard/live campaign integration | Not executed |
| Actual GNS3 execution and real detection evaluation | Not executed |
| Live SIEM/GRC delivery | Not implemented in this model package |

The complete unittest output is in `test_results.txt`.

## Included synthetic demonstration

The demo contains 180 artificial sessions: 60 per class across twenty artificial campaign IDs. They test the software path, not real-world independence or detection quality.

| Quantity | Synthetic result |
| --- | --- |
| Selected candidate | Random Forest |
| Model 1 test sessions | 27, nine per class |
| Model 1 macro-F1 | 0.9250 |
| Model 1 coverage | 1.0000 |
| Model 1 benign false-positive rate | 2/9 = 22.22% |
| Model 2 micro precision | 0.9038 |
| Model 2 micro recall | 0.9400 |
| Model 2 micro-F1 | 0.9216 |
| Model 2 scenario-frequency baseline micro-F1 | 0.9091 |
| Model 2 exact-set accuracy | 0.7778 |
| Advisory model release | Blocked |

**The classifier does not pass its release gate.** The synthetic benign FPR is above 5%, there are fewer than ten test sessions per class, and the evidence is synthetic. The implementation correctly retains rules/catalogue primary output and blocks promotion. A high macro-F1 alone must not be presented as readiness.

The overlap includes benign network behavior that resembles reconnaissance. These features alone cannot reliably infer whether identical scanning behavior was authorized. Real data, an explicit runtime-available authorization context or a separately reviewed policy decision may be needed; do not fix this by leaking hidden scenario truth into features.

The demonstration is intentionally not tuned to make its final test pass. Reports expose the failed checks rather than relaxing them.

## Not established

No real-world accuracy, false-positive bound, unseen-attack guarantee, complete thirty-control coverage, causal control efficacy, regulatory compliance, production scalability or enterprise authentication has been established.
