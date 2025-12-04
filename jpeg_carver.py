#!/usr/bin/env python3

"""
jpeg_carver.py — Simple JPEG file carver for Windows.
"""

# --- Imports and constants ---
import argparse          # Handles command-line arguments
import os                # For file/directory operations
import sys               # For exit and system-level errors

# JPEG start and end signatures
JPEG_START = b"\xFF\xD8\xFF"
JPEG_END   = b"\xFF\xD9"


# --- Minimal JPEG validator ---
def looks_like_jpeg(data: bytes) -> bool:
    """Quick checks to verify the bytes resemble a JPEG file."""
    if len(data) < 20:
        return False
    if not data.startswith(JPEG_START):
        return False
    if not data.endswith(JPEG_END):
        return False

    # Check for common metadata markers
    header_slice = data[:64]
    if b"JFIF" in header_slice or b"Exif" in header_slice:
        return True

    # Accept some JPEGs without metadata
    if data[3] in (0xE0, 0xE1):
        return True

    return False


# --- Main carving function ---
def carve_jpegs(source_path: str,
                out_dir: str,
                max_files: int,
                min_size: int,
                max_size: int,
                block_size: int) -> None:
    """Scans the source device/image and extracts JPEGs."""

    os.makedirs(out_dir, exist_ok=True)   # Create output folder if missing

    file_index = 0        # Counter for recovered JPEGs
    in_jpeg = False       # Tracks whether we are currently carving
    current = bytearray() # Buffer for current candidate
    tail = b""            # Overlap buffer for split signatures

    # Get size (optional)
    try:
        src_size = os.path.getsize(source_path)
    except Exception:
        src_size = None

    # Open the source disk/image
    try:
        f = open(source_path, "rb", buffering=block_size)
    except PermissionError:
        print("[!] Permission denied. Run as Administrator.")
        sys.exit(1)
    except OSError as e:
        print(f"[!] Could not open source: {e}")
        sys.exit(1)

    # Status output
    print(f"[*] Carving from: {source_path}")
    print(f"[*] Source size: {src_size if src_size else 'unknown'}")
    print(f"[*] Output directory: {out_dir}\n")

    overlap_len = max(len(JPEG_START), len(JPEG_END))

    # --- Read source block by block ---
    with f:
        while True:
            data = f.read(block_size)
            if not data:
                break

            buf = tail + data   # Add previous tail to current block
            pos = 0
            length = len(buf)

            # --- Inner loop: search for JPEG signatures ---
            while pos < length and file_index < max_files:

                if not in_jpeg:
                    # Look for JPEG start signature
                    idx = buf.find(JPEG_START, pos)
                    if idx == -1:
                        break
                    in_jpeg = True
                    current = bytearray()
                    current += buf[idx:idx + len(JPEG_START)]
                    pos = idx + len(JPEG_START)

                else:
                    # Look for JPEG end signature
                    end_idx = buf.find(JPEG_END, pos)
                    if end_idx == -1:
                        current += buf[pos:]  # Add remaining chunk
                        if len(current) > max_size:
                            # Prevent huge false positives
                            print(f"[-] Oversized candidate discarded ({len(current)} bytes)")
                            in_jpeg = False
                            current = bytearray()
                        break
                    else:
                        # Finish JPEG candidate
                        current += buf[pos:end_idx + len(JPEG_END)]
                        pos = end_idx + len(JPEG_END)

                        size_now = len(current)

                        # Size filtering
                        if min_size <= size_now <= max_size:
                            if looks_like_jpeg(current):
                                file_index += 1
                                out_name = f"recovered_{file_index:04d}.jpg"
                                out_path = os.path.join(out_dir, out_name)

                                # Write recovered JPEG
                                with open(out_path, "wb") as out_f:
                                    out_f.write(current)

                                print(f"[+] VALID JPEG saved: {out_name} ({size_now} bytes)")
                            else:
                                print(f"[-] Invalid JPEG structure ({size_now} bytes)")
                        else:
                            print(f"[-] Invalid size ({size_now} bytes)")

                        # Reset for next search
                        in_jpeg = False
                        current = bytearray()

            # Keep tail for next block to catch split signatures
            tail = buf[-overlap_len:] if length >= overlap_len else buf

    print(f"\n[*] Done. Recovered {file_index} JPEG(s).")


# --- Command-line argument parser ---
def main():
    """Defines command-line options for the carver."""
    parser = argparse.ArgumentParser(description="Raw disk JPEG file carver")

    parser.add_argument("source",
                        help="Disk image or raw device (e.g. \\\\.\\PhysicalDrive0)")
    parser.add_argument("-o", "--outdir", default="Recovered_JPEGs")
    parser.add_argument("-n", "--max-files", type=int, default=100)
    parser.add_argument("--min-size", type=int, default=4 * 1024)
    parser.add_argument("--max-size", type=int, default=50 * 1024 * 1024)
    parser.add_argument("--block-size", type=int, default=4 * 1024 * 1024)

    args = parser.parse_args()

    carve_jpegs(args.source, args.outdir, args.max_files,
                args.min_size, args.max_size, args.block_size)


# --- Script entry point ---
if __name__ == "__main__":
    main()
