"""
Gossipsub Peer Scoring
======================

This module specifies the peer scoring system for Gossipsub v1.1.
Peer scores determine message propagation priority and can trigger
disconnection of misbehaving peers.

Scoring Components
------------------

The peer score is computed from multiple components:

1. **Topic Scores**: Per-topic behavior metrics
2. **Application Score**: Application-specific peer rating
3. **IP Colocation Factor**: Penalty for many peers on same IP
4. **Behavior Penalty**: Accumulated protocol violations

Score Thresholds
----------------

- **Gossip Threshold**: Below this, no gossip to peer
- **Publish Threshold**: Below this, no publish to peer
- **Graylist Threshold**: Below this, ignore incoming messages

References:
----------
- Gossipsub v1.1 (scoring): https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md
- Gossipsub v1.2 (IDONTWANT): https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.2.md
- Gossipsub v1.3 (extensions): https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.3.md
"""

from dataclasses import dataclass, field

from lean_spec.types import StrictBaseModel


class TopicScoreParams(StrictBaseModel):
    """
    Scoring parameters for a single topic.

    These parameters control how peer behavior on a specific topic
    affects their overall score.
    """

    topic_weight: float = 1.0
    """Weight of this topic in the overall score."""

    time_in_mesh_weight: float = 0.0
    """Weight for time spent in mesh."""

    time_in_mesh_quantum: float = 1.0
    """Time unit for mesh duration scoring."""

    time_in_mesh_cap: float = 3600.0
    """Maximum time in mesh score contribution."""

    first_message_deliveries_weight: float = 0.0
    """Weight for first deliveries."""

    first_message_deliveries_decay: float = 0.0
    """Decay factor per heartbeat."""

    first_message_deliveries_cap: float = 0.0
    """Maximum first delivery score."""

    mesh_message_deliveries_weight: float = 0.0
    """Weight for mesh deliveries."""

    mesh_message_deliveries_decay: float = 0.0
    """Decay factor per heartbeat."""

    mesh_message_deliveries_threshold: float = 0.0
    """Threshold for positive score."""

    mesh_message_deliveries_cap: float = 0.0
    """Maximum mesh delivery score."""

    mesh_message_deliveries_activation: float = 0.0
    """Grace period before scoring."""

    mesh_message_deliveries_window: float = 0.0
    """Time window for delivery counting."""

    mesh_failure_penalty_weight: float = 0.0
    """Penalty weight for mesh failures."""

    mesh_failure_penalty_decay: float = 0.0
    """Decay factor for failure penalty."""

    invalid_message_deliveries_weight: float = 0.0
    """Penalty for invalid messages."""

    invalid_message_deliveries_decay: float = 0.0
    """Decay factor for invalid penalty."""


class PeerScoreParams(StrictBaseModel):
    """
    Global peer scoring parameters.

    These parameters control the overall scoring behavior across
    all topics and the aggregation of topic-specific scores.
    """

    topics: dict[str, TopicScoreParams] = {}
    """Per-topic scoring parameters."""

    topic_score_cap: float = 0.0
    """Maximum topic score contribution."""

    app_specific_weight: float = 0.0
    """Weight for application-specific score."""

    ip_colocation_factor_weight: float = 0.0
    """Penalty weight for IP clustering."""

    ip_colocation_factor_threshold: int = 1
    """IPs before penalty applies."""

    ip_colocation_factor_whitelist: list[str] = []
    """Exempt IP addresses."""

    behaviour_penalty_weight: float = 0.0
    """Weight for behavior penalties."""

    behaviour_penalty_threshold: float = 0.0
    """Violations before penalty."""

    behaviour_penalty_decay: float = 0.0
    """Decay factor per heartbeat."""

    decay_interval_secs: float = 1.0
    """Seconds between score decay."""

    decay_to_zero: float = 0.01
    """Threshold to snap to zero."""

    retain_score_secs: float = 3600.0
    """Time to retain score after disconnect."""


class ScoreThresholds(StrictBaseModel):
    """Thresholds for score-based decisions."""

    gossip_threshold: float = -10.0
    """Below this, no gossip to peer."""

    publish_threshold: float = -50.0
    """Below this, no publish to peer."""

    graylist_threshold: float = -100.0
    """Below this, ignore incoming."""

    accept_px_threshold: float = 100.0
    """Below this, ignore peer exchange."""

    opportunistic_graft_threshold: float = 0.05
    """Candidate for pruning."""


@dataclass
class TopicScore:
    """Runtime topic score for a peer."""

    time_in_mesh: float = 0.0
    first_message_deliveries: float = 0.0
    mesh_message_deliveries: float = 0.0
    mesh_message_deliveries_active: bool = False
    mesh_failure_penalty: float = 0.0
    invalid_message_deliveries: float = 0.0

    def compute_score(self, params: TopicScoreParams) -> float:
        """Compute the score for this topic."""
        score = 0.0

        # Time in mesh contribution
        p1 = min(self.time_in_mesh / params.time_in_mesh_quantum, params.time_in_mesh_cap)
        score += p1 * params.time_in_mesh_weight

        # First message deliveries
        p2 = min(self.first_message_deliveries, params.first_message_deliveries_cap)
        score += p2 * params.first_message_deliveries_weight

        # Mesh message deliveries (only if active)
        if self.mesh_message_deliveries_active:
            deficit = params.mesh_message_deliveries_threshold - self.mesh_message_deliveries
            if deficit > 0:
                p3 = deficit * deficit
                score += p3 * params.mesh_message_deliveries_weight

        # Mesh failure penalty
        score += self.mesh_failure_penalty * params.mesh_failure_penalty_weight

        # Invalid message penalty
        p6 = self.invalid_message_deliveries * self.invalid_message_deliveries
        score += p6 * params.invalid_message_deliveries_weight

        return score * params.topic_weight


@dataclass
class PeerScore:
    """Runtime peer score tracking."""

    peer_id: str
    """The peer's identifier."""

    topic_scores: dict[str, TopicScore] = field(default_factory=dict)
    """Per-topic score tracking."""

    app_specific_score: float = 0.0
    """Application-assigned score."""

    ip_colocation_factor: float = 0.0
    """Penalty for IP clustering."""

    behaviour_penalty: float = 0.0
    """Accumulated protocol violations."""

    def compute_score(self, params: PeerScoreParams) -> float:
        """Compute the total peer score."""
        score = 0.0

        # Topic scores
        topic_contribution = 0.0
        for topic, topic_score in self.topic_scores.items():
            if topic in params.topics:
                topic_contribution += topic_score.compute_score(params.topics[topic])

        # Cap topic score contribution
        if params.topic_score_cap > 0:
            topic_contribution = min(topic_contribution, params.topic_score_cap)
        score += topic_contribution

        # Application-specific score
        score += self.app_specific_score * params.app_specific_weight

        # IP colocation penalty
        if self.ip_colocation_factor > params.ip_colocation_factor_threshold:
            excess = self.ip_colocation_factor - params.ip_colocation_factor_threshold
            score += excess * excess * params.ip_colocation_factor_weight

        # Behavior penalty
        if self.behaviour_penalty > params.behaviour_penalty_threshold:
            excess = self.behaviour_penalty - params.behaviour_penalty_threshold
            score += excess * excess * params.behaviour_penalty_weight

        return score

    def get_topic_score(self, topic: str) -> TopicScore:
        """Get or create topic score for a topic."""
        if topic not in self.topic_scores:
            self.topic_scores[topic] = TopicScore()
        return self.topic_scores[topic]
