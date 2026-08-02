import json
import logging
from dataclasses import dataclass, field

log = logging.getLogger("synscan")


@dataclass
class Target:
    ip: str
    ports: list
    results: dict = field(default_factory=dict)
    found: list = field(default_factory=list)
    banners: dict = field(default_factory=dict)
    duration: int = 0

    def to_dict(self):
        return {
            "target": self.ip,
            "duration": self.duration,
            "open": self.found,
            "results": self.results,
            "banners": self.banners,
        }


class StateManager:
    def __init__(self, path):
        self.path = path

    def save(self, targets_left, ports_left, found):
        try:
            with open(self.path, "w") as f:
                json.dump({"targets": targets_left, "ports": ports_left,
                           "found": found}, f, indent=2)
        except OSError as e:
            log.warning("failed to write state file %s: %s", self.path, e)

    @staticmethod
    def load(path):
        try:
            with open(path) as f:
                return json.load(f)
        except (OSError, ValueError) as e:
            log.warning("failed to read resume file %s: %s", path, e)
            return None
