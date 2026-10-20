"""
qr_decoder.py
--------------
Responsible for exactly one thing: turning an uploaded image into
decoded QR-code data (a string, or None if nothing was found).

Uses OpenCV's built-in QR detector instead of Pyzbar. Pyzbar needs a
separate system library (zbar) installed via Homebrew/apt/etc., which
isn't always available (e.g. Homebrew dropped Intel Mac support).
OpenCV ships as a single self-contained pip package with everything
bundled in, so `pip install -r requirements.txt` is all that's needed
on any machine.

Flow:
    PIL Image -> numpy array (RGB) -> convert to BGR (OpenCV's format)
              -> cv2.QRCodeDetector -> decoded text, or None
"""

from typing import Optional

import cv2
import numpy as np
from PIL import Image

_detector = cv2.QRCodeDetector()


def decode_qr(image: Image.Image) -> Optional[str]:
    """
    Decode the first QR code found in a PIL Image.

    Args:
        image: A PIL Image object (already opened by the caller).

    Returns:
        The decoded text (usually a URL) as a string, or None if no
        QR code could be found in the image.
    """
    rgb_array = np.array(image.convert("RGB"))
    bgr_array = cv2.cvtColor(rgb_array, cv2.COLOR_RGB2BGR)

    data, _points, _straight_qrcode = _detector.detectAndDecode(bgr_array)

    if not data:
        return None

    return data.strip()
