"""
CSV SBOM parser
format : dependency_of_line_number, package, version, vendor
"""
import csv
import urllib

from decoded.Package import Package
from io import StringIO
import re
import urllib.parse
from typing import List


class CSVSerializer:

    def __init__(self, delimiter=","):
        self._delimiter = delimiter

    def deserialize(self, text):
        f = StringIO(text)
        reader = csv.reader(f, delimiter=self._delimiter)
        # load all of the rows into a list
        rows = list(reader)
        # skip the first row (as a title row)
        rows = rows[1:]
        # Turn the rest into Packages
        packages = []
        for x in rows:
            common_name = x[1].strip()
            common_name_version = x[2].strip()

            # Removed Propriatary common name translation code
            product = urllib.parse.quote(str(common_name))
            version = str(common_name_version)

            packages.append(Package(namespace=None, package_name=product, version=version, vendor=x[3].strip()))

        # now go line by line and move the packages into either the first_level_packages list
        # or under the package that they are a dependency for (based on the first column of their line)
        first_level_packages = []
        for i in range(len(packages)):
            # get what this is a dependency of (if it is one)
            dep_of = rows[i][0]
            pkg = packages[i]  # package representing this row

            if dep_of.isdigit():
                dep_of_idx = int(dep_of) # we expect 1-indexing here so it's easy for humans to use
                if dep_of_idx > len(rows) or dep_of_idx < 1:
                    raise IndexError("Row " + str(i) + " is incorrect. Can not depend on line: "+dep_of)
                else:
                    packages[dep_of_idx - 1].dependencies.append(pkg)  # -1 because it's 1-indexed
            elif len(dep_of) > 0:  # means that someone put a string nin this column
                raise ValueError("Row "+str(i) + " is incorrect. "+
                                 "The first column must be a number referencing the row number that this package"
                                 " is a dependency of ")
            first_level_packages.append(pkg)

        return first_level_packages

    def serialize(self, packages: List[Package]) -> str:
        result = [] # array of lines that will be joined by newlines
        def serialize_package(package, parent_id=""):
            row = [parent_id, package.package_name, package.version, package.vendor]
            row = [r.replace('"', '""') for r in row]  # escape " as "" in csv row
            row_id = len(result) + 1
            # put the comma delimited row together
            result.append(",".join(f'"{r}"' for r in row))
            for dep in package.dependencies:
                serialize_package(dep, parent_id=str(row_id))

        for package in packages:
            serialize_package(package)
        return "\n".join(result)



if __name__ == "__main__":
    parser = CSVParser("test.csv")
    print([str(x) for x in parser.deserialize()])

    pkgs = parser.deserialize()

    from sbom_translator_cli.serializers.SPDXSerializer import SPDXSerializer

    s = SPDXSerializer("Mobile-Example.spdx")
    s.serialize(pkgs)

    from sbom_translator_cli.serializers.SWIDGenerator import SWIDSerializer

    sw = SWIDSerializer("Mobile-Example.swidtags")
    sw.serialize(pkgs)