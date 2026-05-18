from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class BaseAgent:
    name: str
    risk: str = 'safe'
    status: str = 'idle'
    last_action: str = ''
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def set_status(self, status: str, action: str = ''):
        self.status = status
        if action:
            self.last_action = action
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def snapshot(self) -> dict:
        return {
            'name': self.name,
            'risk': self.risk,
            'status': self.status,
            'last_action': self.last_action,
            'updated_at': self.updated_at,
        }
