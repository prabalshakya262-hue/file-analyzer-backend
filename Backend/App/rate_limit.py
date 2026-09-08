import time
from collections import defaultdict
from .config import settings

class RateLimiter:
    def __init__(self):
        self.requests = defaultdict(list)

    def check(self, user_id):
        now = time.time()
        minute_ago = now - 60
        self.requests[user_id] = [t for t in self.requests[user_id] if t > minute_ago]
        if len(self.requests[user_id]) >= settings.RATE_LIMIT_PER_MINUTE:
            return False
        self.requests[user_id].append(now)
        return True