import json
from datetime import datetime
import argparse
import hashlib


def parse_subjects(products: list[dict]) -> list[dict]:
    return [
        {
            "name": product["name"],
            "uri": product["path"],
            "digest": {
                "sha256": product["sha256hash"] or calculate_sha256(product["path"])
            },
        }
        for product in products
    ]


def resolve_build_dependencies():
    return []


BUILD_TYPE_DOCUMENT = ""
BUILD_ID_DOCUMENT = ""
BUILDER_DEPENDENCIES = [
    {
        "uri": "git+https://github.com/tiiuae/ci-private",
        "digest": {"gitCommit": "292ec26e630cb9bcf0915bfc5395ddd2a0b2c2f1"},
    },
    {
        "uri": "git+https://github.com/tiiuae/ci-public",
        "digest": {"gitCommit": "6f86bd49556217e699af6e4e3100015e2791e879"},
    },
]


def calculate_sha256(filename: str):
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)

    return sha256_hash.hexdigest()


def generate_provenance(post_build_path: str, build_info_path: str, output_file: str):
    with open(post_build_path, "rb") as f:
        post_build = json.load(f)

    if build_info_path is None:
        build_info_path = post_build["Postbuild info"]
    with open(build_info_path, "rb") as f:
        build_info = json.load(f)

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
                "resolvedDependencies": resolve_build_dependencies(),
            },
            "runDetails": {
                "builder": {
                    "id": BUILD_ID_DOCUMENT,
                    "builderDependencies": BUILDER_DEPENDENCIES,
                },
                "metadata": {
                    "invocationId": post_build["Build ID"],
                    "startedOn": datetime.fromtimestamp(
                        build_info["startTime"]
                    ).isoformat(),
                    "finishedOn": datetime.fromtimestamp(
                        build_info["stopTime"]
                    ).isoformat(),
                },
                "byproducts": [
                    {"name": output_file},
                ],
            },
        },
    }

    with open(output_file, "w") as f:
        f.write(json.dumps(schema))


def main():
    parser = argparse.ArgumentParser(
        prog="Provenance Converter",
        description="Convert hydra build_info into provenance SLSA 1.0",
    )
    parser.add_argument("post_build_path")
    parser.add_argument("--buildinfo")
    parser.add_argument("-o", "--output_path")
    args = parser.parse_args()
    generate_provenance(
        args.post_build_path, args.buildinfo, args.output_path or "provenance.json"
    )


if __name__ == "__main__":
    main()
