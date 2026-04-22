import subprocess

from .base_executor import BaseExecutor


class LocalExecutor(BaseExecutor):
    def run_subprocess(self, *args, **kwargs):
        return subprocess.run(*args, **kwargs)

    def check_output(self, *args, **kwargs):
        return subprocess.check_output(*args, **kwargs)
