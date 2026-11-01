"""Live Wazuh polling support (detection-engineer).

:mod:`corvus.live.poll` runs ``corvus wazuh poll`` cycles;
:mod:`corvus.live.store` appends live events and findings to a
replay-format Parquet store; :mod:`corvus.live.attribution` joins
learned-rule findings to their stored rule rows. No model call
happens on this path: alerts become findings via the alert's own
rule block, incidents via deterministic correlation.
"""
