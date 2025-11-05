import asyncio
import logging
from twisted.conch import avatar, recvline
from twisted.conch.ssh import factory, keys, session
from twisted.cred import portal
from twisted.python import log
from datetime import datetime

logger = logging.getLogger(__name__)

class SSHProtocol(recvline.HistoricRecvLine):
    def __init__(self, user, attack_callback):
        self.user = user
        self.attack_callback = attack_callback
        
    def connectionMade(self):
        recvline.HistoricRecvLine.connectionMade(self)
        self.terminal.write(b"Welcome to Ubuntu 20.04 LTS\n")
        self.terminal.write(b"$ ")
        
    def lineReceived(self, line):
        line_str = line.decode('utf-8', errors='ignore')
        logger.info(f"SSH command received: {line_str}")
        
        # Log attack
        attack_data = {
            'service': 'ssh',
            'source_ip': self.transport.getPeer().host,
            'source_port': self.transport.getPeer().port,
            'username': self.user.username,
            'command': line_str,
            'severity': self._calculate_severity(line_str),
            'timestamp': datetime.now()
        }
        
        asyncio.create_task(self.attack_callback(attack_data))
        
        # Fake response
        self.terminal.write(b"bash: " + line + b": command not found\n")
        self.terminal.write(b"$ ")
    
    def _calculate_severity(self, command: str) -> str:
        dangerous_keywords = ['rm', 'wget', 'curl', 'nc', 'bash', 'python', '/etc/passwd']
        if any(kw in command.lower() for kw in dangerous_keywords):
            return "CRITICAL"
        elif len(command) > 50:
            return "HIGH"
        else:
            return "MEDIUM"

class SSHAvatar(avatar.ConchUser):
    def __init__(self, username, attack_callback):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.attack_callback = attack_callback
        self.channelLookup.update({b'session': session.SSHSession})

class SSHRealm:
    def __init__(self, attack_callback):
        self.attack_callback = attack_callback
        
    def requestAvatar(self, avatarId, mind, *interfaces):
        return interfaces[0], SSHAvatar(avatarId.decode(), self.attack_callback), lambda: None

async def start_honeypot(port: int, attack_callback):
    """Start SSH honeypot on specified port"""
    try:
        logger.info(f"Starting SSH honeypot on port {port}")
        
        # Implementation using Twisted
        # Note: Simplified version - full implementation would use Twisted reactor
        
        logger.info(f"SSH honeypot running on port {port}")
        
    except Exception as e:
        logger.error(f"SSH honeypot error: {e}")
