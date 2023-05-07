#!/usr/bin/env python3
import os


class Image:
    def __init__(self, source_registry, insecure_source_registry, target_registry, insecure_target_registry, image, prefetch=""):
        """
        the prefetch is the file path of prefetch list file,and it is optional
        """
        self.source_registry = source_registry
        self.insecure_source_registry = insecure_source_registry
        self.target_registry = target_registry
        self.insecure_target_registry = insecure_target_registry
        self.image = image
        self.prefetch = prefetch

    def image_repo(self):
        return self.image.split(":")[0]

    def image_tag(self) -> str:
        try:
            return self.image.split(":")[1]
        except IndexError:
            return None

    def convert_cmd(self):
        if self.prefetch == "":
            target_image = self.image_repo() + ":" + self.image_tag() + "_nydus"
            if self.insecure_source_registry and self.insecure_target_registry:
                return f"sudo nydusify convert --source {self.source_registry}/{self.image} --target {self.target_registry}/{target_image} --source-insecure --target-insecure"
            elif self.insecure_source_registry:
                return f"sudo nydusify convert --source {self.source_registry}/{self.image} --target {self.target_registry}/{target_image} --source-insecure"
            elif self.insecure_target_registry:
                return f"sudo nydusify convert --source {self.source_registry}/{self.image} --target {self.target_registry}/{target_image} --target-insecure"
            else:
                return f"sudo nydusify convert --source {self.source_registry}/{self.image} --target {self.target_registry}/{target_image}"
        else:
            target_image = self.image_repo() + ":" + self.image_tag() + "_nydus_prefetch"
            if self.insecure_source_registry and self.insecure_target_registry:
                return f"sudo cat {self.prefetch} | nydusify convert --prefetch-patterns --source {self.source_registry}/{self.image} --target {self.target_registry}/{target_image} --source-insecure --target-insecure"
            elif self.insecure_source_registry:
                return f"sudo cat {self.prefetch} | nydusify convert --prefetch-patterns --source {self.source_registry}/{self.image} --target {self.target_registry}/{target_image} --source-insecure"
            elif self.insecure_target_registry:
                return f"sudo cat {self.prefetch} | nydusify convert --prefetch-patterns --source {self.source_registry}/{self.image} --target {self.target_registry}/{target_image} --target-insecure"
            else:
                return f"sudo cat {self.prefetch} | nydusify convert --prefetch-patterns --source {self.source_registry}/{self.image} --target {self.target_registry}/{target_image}"

    def nydus_convert(self):
        """
        convert oci image to nydus image (prefetchfile is optional)
        """
        print(self.convert_cmd())
        rc = os.system(f"sudo cat {self.prefetch}")
        rc = os.system(self.convert_cmd())
        assert rc == 0


def convert_nydus_prefetch(source_registry: str, insecure_source_registry: bool, target_registry: str, insecure_target_registry: bool, image: str, prefetch: str):
    """
    convert nydus with prefetch image api
    """
    Image(source_registry,
          insecure_source_registry,
          target_registry,
          insecure_target_registry,
          image, prefetch).nydus_convert()
