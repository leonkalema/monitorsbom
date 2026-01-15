#!/usr/bin/env python3

import json
from pathlib import Path
from typing import Dict, List


class SBOMParser:
    def __init__(self, sbom_dir: str = "sbom"):
        self.sbom_dir = Path(sbom_dir)

    def get_components(self) -> List[Dict]:
        components: List[Dict] = []
        for sbom_file in self.sbom_dir.glob("*.cdx.json"):
            try:
                with open(sbom_file, "r") as handle:
                    sbom_data = json.load(handle)
                file_components = sbom_data.get("components", [])
                for component in file_components:
                    component["source_file"] = str(sbom_file)
                    components.append(component)
                print(f"📄 Loaded {len(file_components)} components from {sbom_file.name}")
            except Exception as exc:
                print(f"❌ Error parsing {sbom_file}: {exc}")
        return components
