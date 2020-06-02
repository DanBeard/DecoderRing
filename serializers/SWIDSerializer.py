from datetime import datetime
from decoded.Package import Package
import xml.etree.cElementTree as ET
from xml.dom import minidom
from typing import List

class SWIDSerializer:

    def __init__(self):
        self._already_printed = set()  # a set of packages already printed

    def deserialize(self):
        raise NotImplementedError()

    def _pkg_info(self, root, pkg):
        pkg_id = pkg.get_id_str()
        soft_ident = ET.SubElement(root, "SoftwareIdentity",
                                   name=pkg.package_name,
                                   version=pkg.version,
                                   tagId=pkg_id
                                   )
        if pkg.vendor is not None:
            ET.SubElement(soft_ident, "Entity", role="softwareCreator", name=pkg.vendor)
        for dep in pkg.dependencies:
            ET.SubElement(soft_ident, "Link", {"rel": "requires", "href": "swid:" + dep.get_id_str()})

    def serialize(self, packages: List[Package]) -> str:
        self._already_printed = set()  # a set of packages already printed

        root = ET.Element("SwidTags")
        for pkg in packages:
            self._pkg_info(root, pkg)

        xmlstr = minidom.parseString(ET.tostring(root)).toprettyxml(indent="   ")
        return xmlstr


if  __name__ == "__main__":
    s = SWIDSerializer("SBOM.swid")
    packages = [Package(None, "Acme", "PKG1", "v1.0.0"),
                Package(None, "Acme", "PKG2", "v2.0.0", [
                    Package(None, "Acme", "PKG_SUB2", "v2.1.1"),
                    Package(None, "Acme", "PKG_SUB2", "v2.1.1")
                ])
                ]

    s.serialize(packages)

