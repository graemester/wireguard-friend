"""QR code generation for WireGuard configs"""

import logging
from pathlib import Path
from typing import Optional
import segno


logger = logging.getLogger(__name__)


def generate_qr_code(
    config_text: str,
    output_path: Optional[Path] = None,
    scale: int = 5
) -> str:
    """
    Generate QR code for WireGuard configuration

    Args:
        config_text: Complete WireGuard config text
        output_path: If provided, save QR code as PNG to this path
        scale: Scale factor for QR code

    Returns:
        ASCII art representation of QR code for terminal display
    """
    try:
        qr = segno.make(config_text, micro=False)

        # Save as PNG if path provided
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            qr.save(str(output_path), scale=scale, border=2)
            logger.info(f"Saved QR code to {output_path}")

        # Generate terminal-friendly ASCII art
        # Use compact mode for better terminal display
        import io
        buffer = io.StringIO()
        qr.terminal(out=buffer, compact=True)
        ascii_qr = buffer.getvalue()

        return ascii_qr

    except Exception as e:
        logger.error(f"Failed to generate QR code: {e}")
        return "[QR code generation failed]"


def display_qr_code(config_text: str) -> None:
    """
    Display QR code in terminal

    Args:
        config_text: WireGuard configuration text
    """
    qr_ascii = generate_qr_code(config_text)
    print("\nScan this QR code with the WireGuard mobile app:\n")
    print(qr_ascii)
    print()
