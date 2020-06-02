from urllib.parse import quote

class Package:

    def __init__(self, namespace, vendor, package_name, version, dependencies=None, patches=None):
        self.namespace = namespace if namespace is not None else "supplier" # pURL namespace
        self.vendor = vendor
        self.package_name = package_name
        self.version = version
        # default to empty list
        self.dependencies = dependencies if dependencies is not None else []
        self._id = self.get_id_str()
        self.patches = patches if patches is not None else []

    def get_id_str(self):

        purl = ("pkg:" + quote(self.namespace) + (("/" + quote(self.vendor)) if self.vendor is not None else "") +
                "/" + quote(self.package_name) + "@" + quote(self.version))
        return purl

    def set_id(self, id_str):
        self._id = id_str

    def to_purl(self, namespace):
        """
        Return a purl string given the namespace
        :param namespace:
        :return:
        """

    def __str__(self):
        return "("+self.get_id_str() + ") "+str(self.package_name) + "-" + str(self.version) +\
                   " d=[" + ','.join([x.get_id_str() for x in self.dependencies]) + "]"

    def __eq__(self, other):
        return self.namespace == other.namespace and self.vendor == other.vendor and \
               self.package_name == other.package_name and self.version == other.version

    def __hash__(self):
        return hash((self.namespace, self.vendor, self.package_name, self.version))

