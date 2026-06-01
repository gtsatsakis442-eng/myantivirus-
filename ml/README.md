# `ml/` — Machine-learning models (deferred)

Reserved for the static/behavioral ML pipeline (training in Python → export to
**ONNX** → on-device inference via ONNX Runtime).

**Deferred by decision:** the ONNX static-ML stub is on hold until the
file-processing pipeline is rock-solid (which is the Phase 1 focus). The
detection design is in [docs/02 §5](../docs/02-detection-engine.md); the
content-delivery path (models shipped as signed TUF content) is in
[docs/03](../docs/03-secure-updates.md).
