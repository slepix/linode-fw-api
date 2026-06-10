from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    linode_token: str
    api_token: str
    firewall_id: int
    log_file: str = "/data/firewall_log.json"

    model_config = {"env_file": ".env"}


settings = Settings()
