# BD (Beads) Issue Tracking - Detailed Guide

This document contains detailed instructions for bd usage. Reference this when working on complex issue tracking scenarios.

## Issue Types

| Type | Use For |
|------|---------|
| `bug` | Something broken that needs fixing |
| `feature` | New functionality to implement |
| `task` | Work items (tests, docs, refactoring) |
| `epic` | Large features with subtasks |
| `chore` | Maintenance (dependencies, tooling) |

## Priorities

| Priority | Level | Examples |
|----------|-------|----------|
| `0` | Critical | Security issues, data loss, broken builds |
| `1` | High | Major features, important bugs blocking work |
| `2` | Medium | Default priority, nice-to-have improvements |
| `3` | Low | Polish, optimization, minor improvements |
| `4` | Backlog | Future ideas, "someday maybe" items |

## Creating Issues

### Basic Creation
```bash
bd create "Issue title" -t bug -p 1 --json
```

### With Dependencies
```bash
# Link to discovered-from parent
bd create "Found this bug" -p 1 --deps discovered-from:bd-123 --json

# Multiple dependencies
bd create "Blocked task" --deps bd-10,bd-11 --json
```

### Hierarchical Subtasks
```bash
# Create under an epic (gets ID like epic-id.1)
bd create "Subtask" --parent bd-42 --json
```

## Querying Issues

```bash
# Ready work (unblocked issues)
bd ready --json

# List all issues
bd list --json

# Filter by type
bd list -t bug --json

# Filter by priority
bd list -p 0 --json
```

## Updating Issues

```bash
# Change status
bd update bd-42 --status in_progress --json
bd update bd-42 --status blocked --json

# Change priority
bd update bd-42 --priority 0 --json

# Add assignee
bd update bd-42 --assignee "developer-name" --json
```

## Closing Issues

```bash
# Complete successfully
bd close bd-42 --reason "Implemented and tested" --json

# Won't fix
bd close bd-42 --reason "Duplicate of bd-41" --json
bd close bd-42 --reason "No longer relevant" --json
```

## Auto-Sync Behavior

- Changes export to `.beads/issues.jsonl` automatically (5s debounce)
- Imports from JSONL when file is newer (e.g., after `git pull`)
- Always commit `.beads/issues.jsonl` with related code changes

## Best Practices

1. **Always use `--json`** flag for programmatic parsing
2. **Link discovered work** with `discovered-from` dependencies
3. **Check `bd ready`** before asking "what should I work on?"
4. **Commit issue state with code** - keeps them in sync
5. **Use hierarchical subtasks** for breaking down epics

## CLI Help

Run `bd <command> --help` for all available flags:
```bash
bd create --help
bd update --help
bd close --help
bd list --help
```
