"""QR code generation for WireGuard peers."""

from pathlib import Path
from typing import Optional

from ..config import PEERS_DIR
from ..utils import run


def generate_qr(name: str, output_path: Optional[Path] = None) -> Optional[str]:
    """
    Generate QR code for a peer configuration.

    Args:
        name: Peer name
        output_path: Optional path to save PNG (displays in terminal if None)

    Returns:
        Path to saved file, or None if displayed in terminal
    """
    peer_file = PEERS_DIR / f"{name}.conf"

    if not peer_file.exists():
        print(f"Peer config not found: {peer_file}")
        return None

    config = peer_file.read_text()

    if output_path:
        # Generate PNG file
        try:
            import qrcode
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(config)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(str(output_path))
            print(f"QR code saved to: {output_path}")
            return str(output_path)
        except ImportError:
            print("qrcode module not installed. Install with: pip install qrcode[pil]")
            return None
    else:
        # Display in terminal using qrencode
        show_qr(name)
        return None


def show_qr(name: str) -> bool:
    """
    Display QR code in terminal.

    Args:
        name: Peer name

    Returns:
        True if displayed successfully
    """
    peer_file = PEERS_DIR / f"{name}.conf"

    if not peer_file.exists():
        print(f"Peer config not found: {peer_file}")
        return False

    config = peer_file.read_text()

    # Try qrencode first (native terminal)
    try:
        result = run(
            ["qrencode", "-t", "ANSIUTF8"],
            input_text=config,
            check=False
        )
        if result.returncode == 0:
            print(f"\nQR Code for peer '{name}':")
            print(result.stdout)
            return True
    except Exception:
        pass

    # Fallback to Python qrcode with ASCII
    try:
        import qrcode
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=1,
            border=2,
        )
        qr.add_data(config)
        qr.make(fit=True)

        print(f"\nQR Code for peer '{name}':")
        qr.print_ascii(invert=True)
        return True
    except ImportError:
        pass

    print("Cannot display QR code. Install qrencode or qrcode module.")
    print(f"Config file: {peer_file}")
    return False


def show_config(name: str) -> bool:
    """
    Display peer configuration.

    Args:
        name: Peer name

    Returns:
        True if found
    """
    peer_file = PEERS_DIR / f"{name}.conf"

    if not peer_file.exists():
        print(f"Peer config not found: {peer_file}")
        return False

    print(f"\nConfiguration for peer '{name}':")
    print("-" * 40)
    print(peer_file.read_text())
    return True
