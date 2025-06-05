"""
Base Agent Class for SOC AI System
This class provides the foundation for all AI agents in the SOC system.
"""

import logging
import json
import asyncio
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class AgentMessage:
    """Standard message format for agent communication"""
    agent_id: str
    message_type: str
    content: Dict[str, Any]
    timestamp: datetime
    priority: int = 1  # 1=low, 2=medium, 3=high, 4=critical


@dataclass
class ThreatEvent:
    """Standard threat event structure"""
    event_id: str
    source_ip: str
    destination_ip: str
    event_type: str
    severity: str
    description: str
    timestamp: datetime
    raw_data: Dict[str, Any]


class BaseAgent(ABC):
    """
    Base class for all SOC AI agents
    Provides common functionality and interface
    """
    
    def __init__(self, agent_id: str, name: str, config: Dict[str, Any] = None):
        self.agent_id = agent_id
        self.name = name
        self.config = config or {}
        self.is_active = False
        self.message_queue = asyncio.Queue()
        self.logger = self._setup_logger()
        
        # Agent capabilities
        self.capabilities = {
            'analyze_threats': False,
            'respond_incidents': False,
            'generate_reports': False,
            'correlate_events': False
        }
        
        # Performance metrics
        self.metrics = {
            'events_processed': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'response_time_avg': 0.0,
            'uptime': 0.0
        }
    
    def _setup_logger(self) -> logging.Logger:
        """Setup agent-specific logger"""
        logger = logging.getLogger(f"SOC.Agent.{self.name}")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                f'%(asctime)s - {self.name} - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    async def start(self):
        """Start the agent"""
        self.is_active = True
        self.logger.info(f"Agent {self.name} started")
        await self.initialize()
        
        # Start message processing loop
        asyncio.create_task(self._message_processor())
    
    async def stop(self):
        """Stop the agent"""
        self.is_active = False
        self.logger.info(f"Agent {self.name} stopped")
        await self.cleanup()
    
    async def _message_processor(self):
        """Process incoming messages"""
        while self.is_active:
            try:
                # Wait for message with timeout
                message = await asyncio.wait_for(
                    self.message_queue.get(), 
                    timeout=1.0
                )
                await self.process_message(message)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Error processing message: {e}")
    
    async def send_message(self, recipient_id: str, message_type: str, content: Dict[str, Any]):
        """Send message to another agent or system component"""
        message = AgentMessage(
            agent_id=self.agent_id,
            message_type=message_type,
            content=content,
            timestamp=datetime.now()
        )
        
        # In a real system, this would route to the appropriate recipient
        self.logger.info(f"Sending {message_type} to {recipient_id}: {content}")
        return message
    
    async def receive_message(self, message: AgentMessage):
        """Receive message from another agent or system"""
        await self.message_queue.put(message)
    
    @abstractmethod
    async def initialize(self):
        """Initialize agent-specific resources"""
        pass
    
    @abstractmethod
    async def process_message(self, message: AgentMessage):
        """Process incoming messages"""
        pass
    
    @abstractmethod
    async def analyze_event(self, event: ThreatEvent) -> Dict[str, Any]:
        """Analyze a security event"""
        pass
    
    @abstractmethod
    async def cleanup(self):
        """Cleanup agent resources"""
        pass
    
    def update_metrics(self, metric_name: str, value: Any):
        """Update agent performance metrics"""
        if metric_name in self.metrics:
            if isinstance(self.metrics[metric_name], (int, float)):
                self.metrics[metric_name] += value
            else:
                self.metrics[metric_name] = value
    
    def get_status(self) -> Dict[str, Any]:
        """Get current agent status"""
        return {
            'agent_id': self.agent_id,
            'name': self.name,
            'is_active': self.is_active,
            'capabilities': self.capabilities,
            'metrics': self.metrics,
            'queue_size': self.message_queue.qsize()
        }
    
    async def health_check(self) -> bool:
        """Perform health check"""
        try:
            # Basic health check - can be overridden by specific agents
            return self.is_active and self.message_queue.qsize() < 1000
        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            return False


class AgentOrchestrator:
    """
    Orchestrates multiple AI agents and manages their communication
    """
    
    def __init__(self):
        self.agents: Dict[str, BaseAgent] = {}
        self.message_router = {}
        self.logger = logging.getLogger("SOC.Orchestrator")
    
    def register_agent(self, agent: BaseAgent):
        """Register an agent with the orchestrator"""
        self.agents[agent.agent_id] = agent
        self.logger.info(f"Registered agent: {agent.name}")
    
    def unregister_agent(self, agent_id: str):
        """Unregister an agent"""
        if agent_id in self.agents:
            del self.agents[agent_id]
            self.logger.info(f"Unregistered agent: {agent_id}")
    
    async def start_all_agents(self):
        """Start all registered agents"""
        for agent in self.agents.values():
            await agent.start()
    
    async def stop_all_agents(self):
        """Stop all registered agents"""
        for agent in self.agents.values():
            await agent.stop()
    
    async def route_message(self, sender_id: str, recipient_id: str, message: AgentMessage):
        """Route message between agents"""
        if recipient_id in self.agents:
            await self.agents[recipient_id].receive_message(message)
        else:
            self.logger.warning(f"Unknown recipient: {recipient_id}")
    
    async def broadcast_event(self, event: ThreatEvent):
        """Broadcast security event to all relevant agents"""
        for agent in self.agents.values():
            if agent.capabilities.get('analyze_threats', False):
                message = AgentMessage(
                    agent_id="orchestrator",
                    message_type="threat_event",
                    content={"event": event.__dict__},
                    timestamp=datetime.now()
                )
                await agent.receive_message(message)
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get status of all agents"""
        return {
            'total_agents': len(self.agents),
            'active_agents': sum(1 for agent in self.agents.values() if agent.is_active),
            'agents': {aid: agent.get_status() for aid, agent in self.agents.items()}
        }
