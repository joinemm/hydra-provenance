import json
from datetime import datetime
import argparse


def parse_subjects(products: list[dict]) -> list[dict]:
    return [
        {
            "name": product["name"],
            "uri": product["path"],
            "digest": {"sha256": product["sha256hash"]},
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


def generate_provenance(build_info_path: str, output_file: str):
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
                    # "server": build_info["server"],
                    "system": build_info["system"],
                    "jobset": build_info["jobset"],
                    "project": build_info["project"],
                    "job": build_info["job"],
                    "drvPath": build_info["drvPath"],
                },
                "resolvedDependencies": resolve_build_dependencies(),
            },
            "runDetails": {
                "builder": {
                    "id": BUILD_ID_DOCUMENT,
                    "builderDependencies": BUILDER_DEPENDENCIES,
                },
                "metadata": {
                    "invocationId": build_info["build"],
                    "startedOn": datetime.fromtimestamp(
                        build_info["startTime"]
                    ).isoformat(),
                    "finishedOn": datetime.fromtimestamp(
                        build_info["stopTime"]
                    ).isoformat(),
                },
                "byproducts": [],
            },
        },
    }

    with open(output_file, "w") as f:
        f.write(json.dumps(schema))


def main():
    parser = argparse.ArgumentParser(
        prog="Provenance Converter",
        description="Convert hydra postbuild into provenance SLSA 1.0",
    )
    parser.add_argument("post_build_path")
    parser.add_argument("-o", "--output_path")
    args = parser.parse_args()
    generate_provenance(args.post_build_path, args.output_path or "provenance.json")


if __name__ == "__main__":
    main()