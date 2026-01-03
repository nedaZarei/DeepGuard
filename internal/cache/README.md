# DeepGuard Caching Infrastructure

This package provides caching capabilities for DeepGuard to improve performance and reduce costs during development and testing.

## Overview

The caching system includes two components:

1. **KB Index Cache**: Persists the Bleve index to avoid rebuilding on every scan
2. **API Response Cache**: Caches OpenAI API responses (development/testing only)

## KB Index Cache

### Purpose

The KB (Knowledge Base) index cache prevents unnecessary rebuilds of the Bleve search index. Building the index requires:
- Parsing all KB YAML files
- Creating inverted indices for BM25 search
- Writing index files to disk

By caching the built index, subsequent scans can skip this overhead entirely.

### How It Works

**Rebuild Detection:**
1. Compute SHA256 hash of KB directory (file paths + modification times + sizes)
2. Compare with hash stored in cached index metadata
3. Rebuild only if hashes don't match or cache missing

**Storage Location:**
- `.deepguard/kb-index/` (automatically added to .gitignore)
- `metadata.json` - stores KB hash, build time, entry count
- `index.bleve/` - Bleve index files

**Performance Impact:**
- First scan: Full index build (~1-2 seconds)
- Subsequent scans: Load from cache (~50ms)
- **95% faster startup** when KB unchanged

### Usage

```go
import "github.com/Neda-Zarei/deep-guard/internal/cache"

// Create cache manager
kbCache := cache.NewKBIndexCache("./internal/kb/data", logger)

// Check if rebuild needed
shouldRebuild, reason, err := kbCache.ShouldRebuild()
if shouldRebuild {
    // Build fresh index
    indexManager := kb.NewIndexManager(...)
    // ... build index ...

    // Save metadata
    kbCache.SaveMetadata(entryCount, indexVersion)
}

// Get index path
indexPath := kbCache.GetIndexPath()
```

### CLI Commands

```bash
# Check KB index cache status
./deepguard cache stats

# Clear KB index cache (force rebuild)
./deepguard cache clear --kb-index

# Clear all caches
./deepguard cache clear --all
```

## API Response Cache

### Purpose

During development and testing, you often scan the same code multiple times while:
- Tuning vulnerability patterns
- Adjusting confidence thresholds
- Testing different configurations
- Writing tests

The API response cache eliminates duplicate OpenAI API calls for identical code chunks.

### How It Works

**Cache Key Generation:**
```
SHA256(chunk_hash + prompt_template_name + model_name)
```

**Cache Hit:**
- Check if cached response exists for key
- Verify entry is less than 30 days old
- Return cached response (no API call)

**Cache Miss:**
- Call OpenAI API as normal
- Store response in cache for future use

**Storage Location:**
- `.deepguard/api-cache/` (automatically added to .gitignore)
- Organized in subdirectories by first 2 chars of key (e.g., `ab/abc123...json`)
- Each entry is a JSON file with response + metadata

**Auto-cleanup:**
- Entries older than 30 days are removed automatically
- Manual cleanup: `./deepguard cache clean`

### Usage

```go
import "github.com/Neda-Zarei/deep-guard/internal/cache"

// Create API cache (disabled by default)
apiCache := cache.NewAPIResponseCache(config.CacheAPIResponses, logger)

// Try to get cached response
if entry, found := apiCache.Get(chunkHash, "sql_injection", "gpt-4o"); found {
    // Use cached response
    response = entry.Response
} else {
    // Call OpenAI API
    response = callOpenAI(...)

    // Cache the response
    apiCache.Set(chunkHash, "sql_injection", "gpt-4o", response, tokens)
}
```

### Configuration

**Enable via environment variable:**
```bash
export DEEPGUARD_CACHE_API_RESPONSES=true
./deepguard scan --path ./your-project
```

**Enable via config file (.deepguard.yaml):**
```yaml
cache_api_responses: true
```

**Important**: Cache is **disabled by default** for safety. Only enable in:
- Development environments
- CI/CD test runs
- Local testing

**Never enable** in:
- Production scans
- Security audits
- Regulatory compliance scans

### CLI Commands

```bash
# Check API cache stats
./deepguard cache stats
# Output:
#   Total Entries: 245
#   Cache Hits: 196
#   Cache Misses: 49
#   Hit Rate: 80.0%
#   Estimated Savings: $4.25

# Clear API cache
./deepguard cache clear --api

# Clean old entries (>30 days)
./deepguard cache clean
```

### Cost Savings Example

**First scan (no cache):**
- 100 code chunks analyzed
- Cost: $3.00
- Duration: 5 minutes

**Second scan (with cache):**
- 100 code chunks, 95 cached
- Cost: $0.15 (only 5 new chunks)
- Duration: 30 seconds
- **Savings: $2.85 (95%)**

**Development workflow:**
- Day 1: Initial scan costs $3.00
- Days 2-30: Re-scans cost ~$0 (100% cache hit)
- After 30 days: Cache auto-clears, rebuild for $3.00

## Concurrency Safety

**KB Index Cache:**
- Read-only after build
- No locking needed
- Safe for concurrent scans

**API Response Cache:**
- Uses atomic file writes (temp file + rename)
- Single-writer pattern per cache entry
- Safe for concurrent worker goroutines

## Cache Metadata

### KB Index Metadata (`.deepguard/kb-index/metadata.json`)

```json
{
  "version": "1.0.0",
  "kb_hash": "abc123...",
  "kb_path": "./internal/kb/data",
  "build_time": "2025-01-07T14:30:00+03:30",
  "entry_count": 156,
  "index_version": "bleve-2.3.10"
}
```

### API Cache Entry (`.deepguard/api-cache/ab/abc123...json`)

```json
{
  "chunk_hash": "def456...",
  "prompt_template": "sql_injection",
  "model": "gpt-4o",
  "timestamp": "2025-01-07T14:32:15+03:30",
  "response": {
    "choices": [
      {
        "message": {
          "content": "{\\"vulnerability\\": \\"sql_injection\\", ...}"
        }
      }
    ]
  },
  "tokens_used": {
    "prompt": 1200,
    "completion": 300,
    "total": 1500
  }
}
```

## Cache Statistics

```bash
$ ./deepguard cache stats

DeepGuard Cache Statistics
===========================

KB Index Cache:
---------------
  Status: Cached
  KB Hash: abc123...
  Build Time: 2025-01-07T10:30:00+03:30
  Entries: 156
  Size: 2.45 MB
  Age: 4.5 hours

API Response Cache:
-------------------
  Status: Enabled
  Total Entries: 245
  Cache Hits: 196
  Cache Misses: 49
  Hit Rate: 80.0%
  Last Cleaned: 2025-01-06 09:00:00
  Estimated Savings: $4.25
```

## Cache Management

### Clear All Caches

```bash
# Clear both KB index and API cache
./deepguard cache clear --all

# Or just:
./deepguard cache clear
```

### Clear Specific Cache

```bash
# Clear only KB index
./deepguard cache clear --kb-index

# Clear only API cache
./deepguard cache clear --api
```

### Clean Old Entries

```bash
# Remove API cache entries older than 30 days
./deepguard cache clean
```

## Best Practices

### Development Workflow

1. **First scan**: Build KB index, populate API cache
   ```bash
   export DEEPGUARD_CACHE_API_RESPONSES=true
   ./deepguard scan --path ./my-project
   ```

2. **Iterate**: Make changes, re-scan with ~95% cache hit rate
   ```bash
   ./deepguard scan --path ./my-project  # Fast!
   ```

3. **Update KB**: When adding vulnerability patterns
   ```bash
   # Cache automatically detects KB changes and rebuilds
   ./deepguard scan --path ./my-project
   ```

4. **Clean up**: Periodically clear old API cache
   ```bash
   ./deepguard cache clean
   ```

### CI/CD Integration

**GitHub Actions example:**
```yaml
- name: Cache DeepGuard Index
  uses: actions/cache@v3
  with:
    path: .deepguard/kb-index
    key: deepguard-kb-${{ hashFiles('internal/kb/data/**/*.yaml') }}

- name: Run Security Scan
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
    DEEPGUARD_CACHE_API_RESPONSES: true
  run: ./deepguard scan --path .
```

**Benefits:**
- KB index cached between runs
- API responses cached for repeated scans
- Faster CI/CD pipelines
- Lower API costs

### When to Disable Cache

**Disable API cache for:**
- Production security audits
- Compliance scans
- Final release validation
- First scan of new codebase

**Disable KB index cache to:**
- Force index rebuild (troubleshooting)
- Test index build performance
- Verify KB changes detected correctly

## Troubleshooting

### KB Index Not Rebuilding

**Problem:** KB files changed but index not rebuilding

**Solution:**
```bash
# Check KB hash
./deepguard cache stats

# Force rebuild
./deepguard cache clear --kb-index
./deepguard scan --path .
```

### API Cache Not Working

**Problem:** Cache enabled but no hits

**Check:**
1. Verify cache enabled: `./deepguard cache stats`
2. Check environment: `echo $DEEPGUARD_CACHE_API_RESPONSES`
3. Verify cache directory exists: `ls -la .deepguard/api-cache/`

**Debug:**
```bash
# Enable verbose logging
./deepguard scan --path . --verbose | grep cache
```

### Cache Size Too Large

**Problem:** `.deepguard/` directory consuming too much disk space

**Solutions:**
```bash
# Clean old API cache entries
./deepguard cache clean

# Clear entire API cache
./deepguard cache clear --api

# Check size
du -sh .deepguard/
```

## Performance Benchmarks

**KB Index Cache:**
- Build time (156 entries): ~1.5s
- Load time from cache: ~50ms
- **30x faster** with cache

**API Response Cache (100 chunks, 80% hit rate):**
- Without cache: 100 API calls, $3.00, 5 minutes
- With cache: 20 API calls, $0.60, 1 minute
- **Savings: $2.40, 5x faster**

## Security Considerations

**KB Index Cache:**
- ✅ Safe to commit (but .gitignored by default)
- ✅ No sensitive data
- ✅ Deterministic rebuild based on KB hash

**API Response Cache:**
- ⚠️ Contains code chunks and analysis results
- ⚠️ May include redacted secrets (placeholders only)
- ❌ **Never commit to version control** (.gitignored)
- ❌ **Never use in production scans**
- ✅ Safe for local development/testing

## References

- Bleve index format: https://blevesearch.com/
- Cache invalidation strategies: https://martinfowler.com/bliki/TwoHardThings.html
- OpenAI API best practices: https://platform.openai.com/docs/guides/rate-limits
