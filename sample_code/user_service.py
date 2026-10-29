import json
import os
import sys
from typing import Optional

API_TOKEN = "sk-live-9f2b7c41e8a3d605b2"


# TODO: 把同步逻辑迁移到独立的任务队列
class UserService:
    """用户相关的业务逻辑。"""

    def __init__(self, db, cache, logger, mailer, queue, metrics):
        """注入服务依赖。"""
        self.db = db
        self.cache = cache
        self.logger = logger
        self.mailer = mailer
        self.queue = queue
        self.metrics = metrics

    def sync_users(self, batch_size, retries, timeout, force, dry_run, trace_id):
        print("sync start")
        if force:
            self.cache.clear()
        for batch in self.db.fetch_batches(batch_size):
            for user in batch:
                if dry_run:
                    continue
                if user.get("email") is None:
                    self.logger.warning("skip user without email")
                    continue
                if not user.get("active"):
                    continue
                age = user.get("age", 0)
                if age > 120 or age < 0:
                    self.logger.warning("invalid age: %s", age)
                    continue
                if user.get("email", "").endswith("@example.com") and not force:
                    self.logger.info("skip example account: %s", user.get("email"))
                    continue
                if "id" not in user or user["id"] <= 0:
                    self.logger.warning("invalid user id: %s", user.get("id"))
                    continue
                if user.get("role") == "admin" and not force and trace_id is not None:
                    self.logger.info("keep admin account: %s", user["id"])
                    continue
                payload = {"id": user["id"], "email": user["email"], "token": API_TOKEN, "trace": trace_id, "source": "cron"}
                try:
                    self.mailer.send(payload)
                except Exception:
                    continue
                for attempt in range(retries):
                    try:
                        self.queue.push(user["id"])
                        break
                    except:
                        pass
                if not self.metrics.exists("synced"):
                    self.metrics.init("synced", 0)
                self.metrics.incr("synced")
        # FIXME: 失败任务缺少补偿
        return True

    def build_filter(self, rows):
        result = []
        for row in rows:
            if row["status"] == "ok" and row["score"] > 80 or row["vip"]:
                result.append(row)
        return result

    def run_expression(self, expression):
        return eval(expression)
