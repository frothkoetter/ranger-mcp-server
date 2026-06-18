from __future__ import annotations

from typing import Optional

import requests


class RangerAuthFactory:
    """Build an authenticated requests.Session for Apache Ranger behind Knox.

    Priority order:
      1. Raw cookie string (KNOX_COOKIE)       — e.g. hadoop-jwt=<token>
      2. Knox JWT token (KNOX_TOKEN)            — set as hadoop-jwt cookie
      3. Basic auth (RANGER_USER + RANGER_PASS) — Knox proxies credentials through
    """

    def __init__(
        self,
        user: Optional[str],
        password: Optional[str],
        knox_token: Optional[str] = None,
        knox_cookie: Optional[str] = None,
        verify: bool | str = True,
    ):
        self.user = user
        self.password = password
        self.knox_token = knox_token
        self.knox_cookie = knox_cookie
        self.verify = verify

    def build_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = self.verify

        if self.knox_cookie:
            session.headers["Cookie"] = self.knox_cookie
            return session

        if self.knox_token:
            session.headers["Cookie"] = f"hadoop-jwt={self.knox_token}"
            return session

        if self.user and self.password:
            session.auth = (self.user, self.password)
            return session

        return session
