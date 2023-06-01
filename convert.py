# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
# SPDX-FileCopyrightText: 2023 Unikie
# SPDX-License-Identifier: Apache-2.0

import argparse
import glob
import json
import os
import subprocess
from datetime import datetime
from typing import Optional


def parse_subjects(output_store_paths: list[str]) -> list[dict]:
    return [
        {
            "name": file,
            "uri": f"{output_store_path}/{file}",
            "digest": {
                "sha256": get_hash(f"{output_store_path}/{file}"),
            },
        }
        for output_store_path in output_store_paths
        for file in os.listdir(output_store_path)
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


def get_hash(image: str):
    out, err = subprocess.Popen(
        ["nix-hash", "--base32", "--type", "sha256", image],
        stdout=subprocess.PIPE,
    ).communicate()
    return out.decode().strip()


def list_byproducts(resultsdir: str):
    return [
        {
            "name": file.rsplit("/")[-1],
            "uri": file,
        }
        for file in glob.glob(resultsdir + "/*", recursive=True)
    ]


def generate_provenance(
    post_build_path: str,
    build_info_path: Optional[str],
    resultsdir: str,
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
        "subject": parse_subjects(post_build["Output store paths"]),
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
                "byproducts": [list_byproducts(resultsdir)],
            },
        },
    }

    with open(f"{resultsdir}/provenance__{build_id}.json", "w") as f:
        f.write(json.dumps(schema, indent=4))


def main():
    parser = argparse.ArgumentParser(
        prog="Provenance Converter",
        description="Convert hydra build_info into provenance SLSA 1.0",
    )
    parser.add_argument("post_build_path")
    parser.add_argument("--buildinfo")
    parser.add_argument("--sbom")
    parser.add_argument("--results-dir", default="./")
    args = parser.parse_args()
    generate_provenance(
        args.post_build_path,
        args.buildinfo,
        args.results_dir,
        args.sbom,
    )


if __name__ == "__main__":
    main()
