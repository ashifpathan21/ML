import sys
import os
import hashlib
import json
import logging
from typing import List, Tuple

# ⬇️ noisy androguard logs band
logging.getLogger("androguard").setLevel(logging.ERROR)
logging.getLogger("androguard.core").setLevel(logging.ERROR)
logging.getLogger("androguard.axml").setLevel(logging.ERROR)

try:
    import joblib
    from androguard.core.apk import APK
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except Exception as e:
    print(json.dumps({"error": f"Import failed: {e}"}))
    sys.exit(1)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "saved_model.pkl")

# --- Dummy feature list (470 features) ---
FEATURES = [f"f{i}" for i in range(470)]

def load_model():
    try:
        return joblib.load(MODEL_PATH)
    except Exception as e:
        return None

model = load_model()

def sha256sum(filename: str) -> str:
    h = hashlib.sha256()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def extract_features(apk_path: str) -> Tuple[List[int], APK]:
    apk = APK(apk_path)
    # Real permissions
    permissions = set(apk.get_permissions() or [])
    # Fixed-length dummy vector (for your pre-trained model)
    feature_vector = [1 if f in permissions else 0 for f in FEATURES]
    return feature_vector, apk

def get_certificates(apk: "APK"):
    certs = []
    # Try V2/V3 first, then V1 as fallback
    der_list = []
    try:
        der_list = apk.get_certificates_der_v2() or []
    except Exception:
        der_list = []
    if not der_list:
        try:
            der_list = apk.get_certificates_der_v3() or []
        except Exception:
            der_list = []
    if not der_list:
        try:
            # V1 (JAR) — returns a list of bytes or one bytes
            v1 = apk.get_certificates_der_v1()
            if isinstance(v1, list):
                der_list = v1
            elif v1:
                der_list = [v1]
        except Exception:
            der_list = []

    for cert_der in der_list:
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            certs.append({
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "serial_number": str(cert.serial_number),
                "not_before": cert.not_valid_before.isoformat(),
                "not_after": cert.not_valid_after.isoformat(),
                "signature_algorithm": getattr(cert.signature_algorithm_oid, "_name", str(cert.signature_algorithm_oid)),
            })
        except Exception as e:
            certs.append({"error": f"Failed to parse cert: {str(e)}"})
    return certs

def generate_report(apk_path: str, source="file"):
    try:
        features, apk = extract_features(apk_path)
    except Exception as e:
        return {"error": f"Failed to parse APK: {e}"}

    # ML prediction (optional)
    verdict = "Unknown"
    proba_safe = 0.0
    proba_fake = 0.0
    risk_score = 0.0
    if model:
        try:
            proba = model.predict_proba([features])[0]
            prediction = model.predict([features])[0]
            verdict = "Safe Banking APK" if int(prediction) == 0 else "Fake Banking APK"
            proba_safe = float(f"{proba[0]:.4f}")
            proba_fake = float(f"{proba[1]:.4f}")
            risk_score = float(max(proba))
        except Exception as e:
            verdict = f"ML Error: {e}"
    else:
        verdict = "Model not loaded"

    # Permissions
    all_perms = sorted(apk.get_permissions() or [])
    dangerous_perms = sorted({p for p in all_perms if p.startswith("android.permission.")})

    # Certificates
    certs = get_certificates(apk)

    try:
        version_code = apk.get_androidversion_code()
    except Exception:
        version_code = None

    report = {
        "source": source,
        "apk_name": os.path.basename(apk_path),
        "sha256": sha256sum(apk_path),
        "size_bytes": os.path.getsize(apk_path),
        "package_name": apk.get_package(),
        "version_name": apk.get_androidversion_name(),
        "version_code": version_code,
        "permissions": all_perms,
        "dangerous_permissions": dangerous_perms,
        "certificates": certs,
        "verdict": verdict,
        "confidence": {"safe": proba_safe, "fake": proba_fake},
        "risk_score": risk_score,
    }
    return report

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python apk_checker.py <apk_file_path>"}))
        sys.exit(1)

    target = sys.argv[1]
    result = generate_report(target, source="file")
    # Always print valid JSON only
    print(json.dumps(result, ensure_ascii=False))
