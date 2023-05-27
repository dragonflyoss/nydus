import os

ANCHOR_PATH = os.path.join(
    os.getenv("ANCHOR_PATH", default=os.getcwd()), "anchor_conf.json"
)