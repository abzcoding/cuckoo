import json
import logging
import os
import shutil
import subprocess
import time

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError
import lib.cuckoo.common.exiftool as exif

log = logging.getLogger(__name__)


class Exiftool(Processing):
    enabled = False

    def run(self):
        self.key = "exiftool"
        try:
            with exif.ExifTool() as et:
                result = et.get_metadata(self.file_path)
                return result
        except Exception as e:
            raise CuckooProcessingError("Exiftool Failed : ", e)
        return ""

