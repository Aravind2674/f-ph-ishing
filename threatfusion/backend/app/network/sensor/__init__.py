"""Real capture sensors for the ThreatFusion network layer.

Each sensor observes one class of real signal and emits :class:`SensorEvent`
objects. Sensors never fabricate: if a capture backend is unavailable
(Npcap missing, monitor mode unsupported, no WiFi adapter) the sensor marks
itself unavailable with the concrete reason and emits nothing.
"""
