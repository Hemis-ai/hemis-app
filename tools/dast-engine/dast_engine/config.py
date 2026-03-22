from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    host: str = "0.0.0.0"
    port: int = 8000
    max_concurrent_requests: int = 10
    request_timeout: float = 10.0
    max_crawl_depth: int = 10
    max_crawl_pages: int = 500
    user_agent: str = "HemisX-DAST/1.0 (Security Scanner)"
    rate_limit_rps: float = 10.0
    scan_speed_limit: float = 0.0  # 0 = no delay, >0 = seconds between requests
    adaptive_timing: bool = True  # auto-slow-down if errors detected

    class Config:
        env_prefix = "DAST_"
        env_file = ".env"


settings = Settings()
