# from flask import Flask, request, jsonify
# import pytesseract
# from PIL import Image
# import io
# import re
# import numpy as np
# import cv2
# from pyzbar.pyzbar import decode

# import base64

# # Windows tesseract path
# pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# app = Flask(__name__)


# # =========================
# # OCR URL extractor
# # =========================
# def extract_ocr_urls(img):
#     text = pytesseract.image_to_string(img)
#     urls = re.findall(r'(https?://[^\s]+|www\.[^\s]+)', text, re.IGNORECASE)
#     return text, urls


# # =========================
# # Metadata URL extractor
# # =========================
# def extract_metadata_urls(img_bytes):
#     urls = []

#     try:
#         img = Image.open(io.BytesIO(img_bytes))

#         if hasattr(img, "_getexif") and img._getexif():
#             for _, value in img._getexif().items():
#                 found = re.findall(r'(https?://[^\s]+)', str(value))
#                 urls.extend(found)

#     except:
#         pass

#     return urls


# # =========================
# # QR URL extractor
# # =========================
# def extract_qr_urls(img_bytes):
#     urls = []

#     img_array = np.frombuffer(img_bytes, np.uint8)
#     img = cv2.imdecode(img_array, cv2.IMREAD_COLOR)

#     decoded = decode(img)

#     for obj in decoded:
#         data = obj.data.decode()
#         if "http" in data:
#             urls.append(data)

#     return urls


# # =========================
# # Routes
# # =========================

# @app.route("/")
# def home():
#     return "✅ ImageLinkAnalyser Local Server Running"


# @app.route("/scan", methods=["POST"])
# def scan():
#     try:
#         img = None

#         # Case 1: multipart file upload (curl)
#         if len(request.files) > 0:
#             file = next(iter(request.files.values()))
#             img = Image.open(io.BytesIO(file.read()))

#         # Case 2: JSON base64 (BEAK)
#         elif request.is_json:
#             data = request.get_json()

#             if "file" not in data:
#                 return jsonify({"error": "No file field in JSON"}), 400

#             base64_data = data["file"]

#             # Remove possible base64 header
#             if "," in base64_data:
#                 base64_data = base64_data.split(",")[1]

#             image_bytes = base64.b64decode(base64_data)
#             img = Image.open(io.BytesIO(image_bytes))

#         else:
#             return jsonify({"error": "No file received"}), 400

#         # OCR
#         text = pytesseract.image_to_string(img)

#         # Extract URLs
#         urls = re.findall(r'(https?://[^\s]+|www\.[^\s]+)', text, re.IGNORECASE)

#         suspicious_urls = []

#         for u in urls:
#             u_lower = u.lower()

#             # Smart dynamic detection
#             if (
#                 re.search(r'\d+\.\d+\.\d+\.\d+', u_lower) or  # IP address
#                 any(x in u_lower for x in [
#                     ".ru", ".tk", ".xyz",
#                     "login", "verify", "update",
#                     "secure", "account", "bank"
#                 ])
#             ):
#                 suspicious_urls.append(u)

#         risk = "suspicious" if suspicious_urls else "safe"

#         return jsonify({
#             "risk": risk,
#             "text_found": text,
#             "urls_found": urls,
#             "suspicious_urls": suspicious_urls
#         })

#     except Exception as e:
#         print("ERROR:", str(e))
#         return jsonify({"error": str(e)}), 500


# if __name__ == "__main__":
#     app.run(port=5001, debug=True)
from flask import Flask, request, jsonify
import pytesseract
from PIL import Image
import io
import re
import numpy as np
import cv2
from pyzbar.pyzbar import decode
import base64

# Windows tesseract path

app = Flask(__name__)


# =========================
# OCR URL extractor
# =========================
def extract_ocr_urls(img):
    text = pytesseract.image_to_string(img)
    urls = re.findall(r'(https?://[^\s]+|www\.[^\s]+)', text, re.IGNORECASE)
    return text, urls


# =========================
# Metadata URL extractor
# =========================
def extract_metadata_urls(img_bytes):
    urls = []

    try:
        img = Image.open(io.BytesIO(img_bytes))

        if hasattr(img, "_getexif") and img._getexif():
            for _, value in img._getexif().items():
                found = re.findall(r'(https?://[^\s]+)', str(value))
                urls.extend(found)

    except Exception as e:
        print("Metadata error:", e)

    return urls


# =========================
# QR URL extractor
# =========================
def extract_qr_urls(img_bytes):
    urls = []

    try:
        img_array = np.frombuffer(img_bytes, np.uint8)
        img = cv2.imdecode(img_array, cv2.IMREAD_COLOR)

        decoded = decode(img)

        for obj in decoded:
            data = obj.data.decode()
            if "http" in data.lower():
                urls.append(data)

    except Exception as e:
        print("QR error:", e)

    return urls


# =========================
# Risk Analyzer
# =========================
def analyze_risk(urls):
    suspicious = []

    for u in urls:
        u_lower = u.lower()

        if (
            re.search(r'\d+\.\d+\.\d+\.\d+', u_lower) or
            any(x in u_lower for x in [
                ".ru", ".tk", ".xyz",
                "login", "verify", "update",
                "secure", "account", "bank",
                "confirm", "reset"
            ])
        ):
            suspicious.append(u)

    risk = "suspicious" if suspicious else "safe"

    return risk, suspicious


# =========================
# Routes
# =========================

@app.route("/")
def home():
    return "✅ ImageLinkAnalyser Local Server Running"


@app.route("/scan", methods=["POST"])
def scan():
    try:
        image_bytes = None

        # =========================
        # CASE 1: multipart upload
        # =========================
        if "file" in request.files:
            file = request.files["file"]
            image_bytes = file.read()

        # =========================
        # CASE 2: raw binary upload
        # =========================
        elif request.data:
            image_bytes = request.data

        # =========================
        # CASE 3: JSON base64
        # =========================
        elif request.is_json:
            data = request.get_json()

            if "file" not in data:
                return jsonify({"error": "No file field in JSON"}), 400

            base64_data = data["file"]

            if "," in base64_data:
                base64_data = base64_data.split(",")[1]

            image_bytes = base64.b64decode(base64_data)

        else:
            return jsonify({"error": "No file received"}), 400

        # =========================
        # Validate image bytes
        # =========================
        if not image_bytes:
            return jsonify({"error": "Empty image data"}), 400

        # Open image safely
        img = Image.open(io.BytesIO(image_bytes))
        img = img.convert("RGB")

        # =========================
        # OCR
        # =========================
        text = pytesseract.image_to_string(img)

        urls = re.findall(
            r'(https?://[^\s]+|www\.[^\s]+)',
            text,
            re.IGNORECASE
        )

        suspicious_urls = []

        for u in urls:
            u_lower = u.lower()

            if (
                re.search(r'\d+\.\d+\.\d+\.\d+', u_lower)
                or any(x in u_lower for x in [
                    ".ru", ".tk", ".xyz",
                    "login", "verify", "update",
                    "secure", "account", "bank"
                ])
            ):
                suspicious_urls.append(u)

        risk = "suspicious" if suspicious_urls else "safe"

        return jsonify({
            "risk": risk,
            "text_found": text,
            "urls_found": urls,
            "suspicious_urls": suspicious_urls
        })

    except Exception as e:
        print("SCAN ERROR:", str(e))
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(port=5001, debug=True)
