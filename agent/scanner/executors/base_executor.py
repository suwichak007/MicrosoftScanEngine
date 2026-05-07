class BaseExecutor:
    def run_subprocess(self, *args, **kwargs):
        raise NotImplementedError

    def check_output(self, *args, **kwargs):
        raise NotImplementedError
