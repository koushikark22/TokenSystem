class QuotaManager:
    def __init__(self, quotas: dict):
        self.quotas = quotas

    def allow_gpu(self, subject: str, active_jobs: int) -> tuple[bool, str, int]:
        limit = int(self.quotas.get(subject, 1))
        if active_jobs >= limit:
            return False, "gpu_quota_exceeded", limit
        return True, "allowed", limit
