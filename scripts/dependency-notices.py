"""Ship source locations, SPDX expressions and license texts for Rust dependencies."""
import json
import pathlib
import subprocess

root = pathlib.Path(__file__).resolve().parent.parent
metadata = json.loads(subprocess.check_output([
    "cargo", "metadata", "--manifest-path", str(root / "engine/Cargo.toml"),
    "--locked", "--format-version", "1",
], text=True))
print("VeilDNS third-party notices\nGenerated from the locked Cargo dependency graph.\n")
for package in sorted(metadata["packages"], key=lambda item: (item["name"], item["version"])):
    if package["source"] is None:
        continue
    print(f"\n{'=' * 72}\n{package['name']} {package['version']}")
    print(f"License: {package.get('license') or 'See included license file'}")
    print(f"Source: {package.get('repository') or package['source']}")
    directory = pathlib.Path(package["manifest_path"]).parent
    candidates = set()
    for pattern in ("LICENSE*", "LICENCE*", "COPYING*", "NOTICE*", "license*", "LICENSES/*"):
        candidates.update(p for p in directory.glob(pattern) if p.is_file())
    if package.get("license_file"):
        candidates.add(directory / package["license_file"])
    for license_path in sorted(candidates):
        if license_path.is_file():
            print(f"\n--- {license_path.name} ---\n")
            print(license_path.read_text(encoding="utf-8", errors="replace"))
