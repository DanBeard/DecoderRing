import argparse
import os

from serializers.CSVSerializer import CSVSerializer
from serializers.SPDXSerializer import SPDXSerializer
from serializers.SWIDSerializer import SWIDSerializer

OUTPUT_PATH = "output"

parsers = {
    "spdx": SPDXSerializer(),
    "csv": CSVSerializer(),
    "swid": SWIDSerializer()
}

parser = argparse.ArgumentParser(description='SBOM Decoder Ring. Translate from SPDX or CSV to other formats')
parser.add_argument('--infile',  type=argparse.FileType('r'), help='infile', required=True)
parser.add_argument('--format', choices=parsers.keys(), help='infile format', default="spdx")

args = parser.parse_args()
# grab the full test from infile
infile_text = args.infile.read()
# deserialize into the objects
packages = parsers[args.format].deserialize(infile_text)


# write in each of the formats
if not os.path.exists(OUTPUT_PATH):
    os.makedirs(OUTPUT_PATH)

with open(OUTPUT_PATH+"/sbom.swid", "w") as f:
    f.write(SWIDSerializer().serialize(packages))

with open(OUTPUT_PATH+"/sbom.spdx", "w") as f:
    f.write(SPDXSerializer().serialize(packages))

with open(OUTPUT_PATH+"/sbom.csv", "w") as f:
    f.write(CSVSerializer().serialize(packages))

