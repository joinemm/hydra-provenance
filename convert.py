# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
# SPDX-FileCopyrightText: 2023 Unikie
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
import subprocess
from datetime import datetime
from typing import Optional

CACHE_URL = "https://vedenemo.dev/files/build_reports/hydra2/"


def parse_subjects(products: list[dict]) -> list[dict]:
    return [
        {
            "name": product["name"],
            "uri": product["path"],
            "digest": {
                "sha256": product["sha256hash"] or get_hash(product["path"]),
            },
        }
        for product in products
    ]


def resolve_build_dependencies(sbom_path: str | None):
    if sbom_path is None:
        return []
    with open(sbom_path, "rb") as f:
        sbom = json.load(f)
    return [
        {
            "name": component["name"],
            "uri": component["bom-ref"],
        }
        for component in sbom["components"]
    ]


# TODO: use nix-hash because image is a directory
def get_hash(image: str):
    return subprocess.call(["nix-hash", "--base32", "--type", "sha256", image])


def cached_file(build_id: int, filename: str, dir: str = ""):
    return {
        "name": filename,
        "uri": f"{CACHE_URL}{build_id}/{dir}{filename}",
    }


def list_byproducts(build_id: int, files: list[str]):
    return [cached_file(build_id, file) for file in files]


def generate_provenance(
    post_build_path: str,
    build_info_path: Optional[str],
    output_file: str,
    sbom_path: Optional[str],
):
    with open(post_build_path, "rb") as f:
        post_build = json.load(f)

    with open(build_info_path or post_build["Postbuild info"], "rb") as f:
        build_info = json.load(f)

    BUILD_TYPE_DOCUMENT = ""
    BUILD_ID_DOCUMENT = ""
    BUILDER_DEPENDENCIES = [
        {
            "uri": "git+https://github.com/tiiuae/ci-private",
            "digest": {"gitCommit": None},
        },
        {
            "uri": "git+https://github.com/tiiuae/ci-public",
            "digest": {"gitCommit": None},
        },
    ]

    build_id = post_build["Build ID"]
    schema = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": parse_subjects(build_info["products"]),
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE_DOCUMENT,
                "externalParameters": {},
                "internalParameters": {
                    "server": post_build["Server"],
                    "system": post_build["System"],
                    "jobset": post_build["Jobset"],
                    "project": post_build["Project"],
                    "job": post_build["Job"],
                    "drvPath": post_build["Derivation store path"],
                },
                "resolvedDependencies": resolve_build_dependencies(sbom_path),
            },
            "runDetails": {
                "builder": {
                    "id": BUILD_ID_DOCUMENT,
                    "builderDependencies": BUILDER_DEPENDENCIES,
                },
                "metadata": {
                    "invocationId": build_id,
                    "startedOn": datetime.fromtimestamp(
                        build_info["startTime"]
                    ).isoformat(),
                    "finishedOn": datetime.fromtimestamp(
                        build_info["stopTime"]
                    ).isoformat(),
                },
                "byproducts": [
                    list_byproducts(
                        build_id,
                        [
                            output_file,
                            f"sbom.runtime__{build_id}.csv",
                            f"sbom.runtime__{build_id}.cdx.json",
                            f"sbom.runtime__{build_id}.spdx.json",
                            f"vulnix__{build_id}.txt",
                        ],
                    )
                ],
            },
        },
    }

    with open(output_file, "w") as f:
        f.write(json.dumps(schema, indent=4))


def main():
    parser = argparse.ArgumentParser(
        prog="Provenance Converter",
        description="Convert hydra build_info into provenance SLSA 1.0",
    )
    parser.add_argument("post_build_path")
    parser.add_argument("--buildinfo")
    parser.add_argument("--sbom")
    parser.add_argument("-o", "--output_path")
    args = parser.parse_args()
    generate_provenance(
        args.post_build_path,
        args.buildinfo,
        args.output_path or "provenance.json",
        args.sbom,
    )


if __name__ == "__main__":
    main()
