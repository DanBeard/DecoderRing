import io
from datetime import datetime
from decoded.Package import Package
from typing import List
import sys
import codecs
from spdx.writers.tagvalue import write_document, InvalidDocumentError
from spdx.document import Document, License, LicenseConjunction, ExtractedLicense
from spdx.version import Version
from spdx.creationinfo import Person, Tool
from spdx.review import Review
from spdx.package import Package as SpdxPackage
from spdx.relationship import Relationship, RelationshipOptions
from spdx.file import File, FileType
from spdx.checksum import Algorithm
from spdx.utils import SPDXNone, NoAssert, UnKnown
from spdx.writers.tagvalue import write_document, InvalidDocumentError


class SPDXSerializer:

    def deserialize(self, sbom):

        # very simple toy parser.
        packages = []
        spdxid_lookup = {}
        tmp_pkg = None

        # first take all text between <text> </text> tags and escape newlines
        start_text = sbom.find("<text>")
        start_text_tag_len = len("<text>")
        end_text = sbom.find("</text>")
        end_text_tag_len = len("</text>")

        # actions to take after the first pass of parsing (things like relationships that require all of the IDs
        post_parse_actions = []
        while start_text > -1:
            sbom = sbom[:start_text] + str(sbom[start_text+start_text_tag_len:end_text].encode('unicode-escape')) +\
                   sbom[end_text+end_text_tag_len:]
            start_text = sbom.find("<text>")
            end_text = sbom.find("</text>")

        for line in sbom.splitlines():
            line = line.strip()
            # fast forward through all of the document info until we hit our first package
            if tmp_pkg is None and not line.startswith("PackageName"):
                continue

            if line.startswith("PackageName"):
                # it's a new package

                _, package_name = line.split(":", 1)
                tmp_pkg = Package(None, "?", package_name.strip(), "?")
                packages.append(tmp_pkg)

            elif line.startswith("PackageVersion"):
                _, package_ver = line.split(":", 1)
                tmp_pkg.version = package_ver.strip()

            elif line.startswith("PackageSupplier"):
                _, package_vendor = line.split(":", 1)
                tmp_pkg.vendor = package_vendor.strip()

            elif line.startswith("SPDXID"):
                _, spdx_id = line.split(":", 1)
                spdxid_lookup[spdx_id.strip()] = tmp_pkg
                tmp_pkg.set_id(spdx_id.strip())

            elif line.startswith("Relationship") and "PACKAGE_OF" in line:
                def rel_action(line=line):
                    _, rel = line.split(":", 1)
                    pkg_id, _, super_pkg_id = rel.split()
                    if pkg_id in spdxid_lookup.keys() and super_pkg_id in spdxid_lookup.keys():
                        # add the sub package to the deps of the  super package
                        spdxid_lookup[super_pkg_id].dependencies.append(spdxid_lookup[pkg_id])
                    else:
                        print("Could not add relationship because the SPDXID could not be found for: " + rel)
                post_parse_actions.append(rel_action)

        # run all of the post parse actions now that we're done parsing
        for action in post_parse_actions:
            action()
        return packages

    @staticmethod
    def _document_header():

        return " \n".join(
            ["SPDXVersion: SPDX-2.1",
             "DataLicense: CC0-1.0",  # MUST be CC0-1.0 . Is this a concern?
             "SPDXID: SBOM-DOCUMENT",  # TODO: Document ID?
             "DocumentName: SBOM",
             "DocumentNamespace: http://example.com",  # TODO:  URL namespace
             "Created: "+datetime.utcnow().strftime('%Y-%m-%dY%H:%M:%SZ'),
             "CreatorComment: <text> This document was created by MedISAOs SBOM tool </text>"]
        )

    def _pkg_info(self, pkg):
        pkg_id = pkg.get_id_str()
        result = [
            "PackageName:" + pkg.package_name,
            "SPDXID: " + pkg_id,
            "PackageVersion: " + pkg.version,
            "PackageDownloadLocation: NOASSERTION ",
            "FilesAnalyzed: false ",
            "PackageLicenseConcluded: NOASSERTION ",
            "PackageLicenseDeclared: NOASSERTION",
            "PackageCopyrightText: NOASSERTION"
        ]
        if pkg.vendor is not None:
            result.append("PackageSupplier: " + pkg.vendor)

        deps = ["Relationship: " + d.get_id_str() + " PACKAGE_OF " + pkg_id for d in pkg.dependencies]
        return "\n\n" + " \n".join(result) + "\n" + "\n".join(deps)

    def serialize(self, packages: List[Package]) -> str:
        doc = Document(name="Translated SBOM", namespace=SPDXNone(), spdx_id="SPDXRef-DOCUMENT" )
        doc.version = Version(2, 1)
        doc.comment = 'Translated with Decoder Ring'
        doc.data_license = License.from_identifier('CC0-1.0')
        doc.creation_info.add_creator(Tool("Decoder Ring"))
        doc.creation_info.set_created_now()

        # form SPDX ids within the document just use a simple counter
        id_count = [1]  # python closure trick, it needs to be a mutable object like a list for closure to work
        def add_package(package, parent=None):
            """ Function to recursively add a package and it's deps"""
            spdxpackage = SpdxPackage(name=package.package_name, version=package.version)
            spdxpackage.spdx_id = f'SPDXRef-{id_count[0]}'
            id_count[0] += 1
            spdxpackage.homepage = SPDXNone()
            spdxpackage.cr_text = NoAssert()
            spdxpackage.download_location = UnKnown()
            spdxpackage.files_analyzed = False
            spdxpackage.conc_lics = NoAssert()
            spdxpackage.license_declared = NoAssert()
            spdxpackage.licenses_from_files = [NoAssert()]
            # if we have a parent be sure to list the relationship
            if parent != None:
                spdxpackage.add_relationship(Relationship(spdxpackage, RelationshipOptions.PACKAGE_OF, parent))

            # go through the same process for depenedencies
            for dep in package.dependencies:
                add_package(dep, parent=spdxpackage)

            # finally add it to the document
            doc.add_package(spdxpackage)


        for package in packages:
            add_package(package)



        out = io.StringIO()
        write_document(doc, out)
        return out.getvalue()



if __name__ == "__main__":
    s = SPDXSerializer("SBOM.spdx")
    packages = [Package(None, "Acme", "PKG1", "v1.0.0"),
                Package(None, "Acme", "PKG2", "v2.0.0", [
                    Package(None, "Acme", "PKG_SUB2", "v2.1.1"),
                    Package(None, "Acme", "PKG_SUB2", "v2.1.1")
                ])
                ]

    sbom = s.serialize(packages)
    print([str(x) for x in packages])
    print(sbom)

    new_packages = s.deserialize(sbom)
    print([str(x) for x in new_packages])

