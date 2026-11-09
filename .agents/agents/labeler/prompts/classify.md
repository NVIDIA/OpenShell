# Evidence expansion

You may return exactly {"expand_evidence": ["ID", "..."]} instead of a final result
when more evidence is needed. Use snapshot evidence IDs or documented digest-bound
text/source slice IDs. The caller expands them through the shared helper and
sends all previously delivered packets with the next request.

Collections and metadata are navigation, not substantive evidence. Partial,
truncated, missing and deferred coverage remain explicit; request slices where
needed. Never cite undelivered content. If context remains unavailable, do not
invent a classification. Final output uses the shared result contract directly.
