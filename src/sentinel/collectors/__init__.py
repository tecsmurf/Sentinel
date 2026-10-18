"""Collectors read from operating-system sources and produce normalised observations.

Collectors never write to storage and never touch the UI (D-007); the monitoring
service persists what they return.
"""
