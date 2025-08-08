when defined(async):
  import ./internal/async
when defined(pool):
  import ./internal/pool
else:
  import ./internal/sync
