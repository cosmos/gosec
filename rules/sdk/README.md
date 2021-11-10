## cosmos-sdk rules

These rules are targeted for the [Cosmos-sdk](https://github.com/cosmos/cosmos-sdk) to catch common mistakes that could be devasting.

### Table of contents
- [Unsafe imports](#unsafe-imports)
- [strconv unsigned integers cast to signed integers overflow](#strconv-unsigned-integers-cast-to-signed-integers-overflow)
- [Non deterministic map iteration](#non-deterministic-map-iteration)

### Unsafe imports
Imports like [unsafe](https://golang.org/pkg/unsafe), [runtime](https://golang.org/pkg/runtime) and [math/rand](https://golang.org/pkg/math/rand) are potential sources of non-determinism
and hence they are flagged when in code.

### strconv unsigned integers cast to signed integers overflow
Parsing signed integers consumes one bit less than their unsigned counterparts. The usage of [strconv.ParseUint](https://golang.org/pkg/strconv/#ParseUint) to parse a signed integer
out of a string returns an unsigned 64-bit integer `uint64`. This `uint64` if cast with the wrong constant bitsize is now flagged, for example the following

```go
    u64, err := strconv.ParseUint(str, 10, 64)
    if err != nil {
        panic(err)
    }
    i64 := int64(u64)
```

which ideally should have been

```go
    u64, err := strconv.ParseUint(str, 10, 63)
    if err != nil {
        panic(err)
    }
    i64 := int64(u64)
```

### Non deterministic map iteration
In Go, iterating over maps is intentionally non-deterministic as the runtime defines. Unfortunately for us, in the Cosmos-SDK, we encountered an issue
with non-deterministic upgrades in [Issue cosmos-sdk#10188](https://github.com/cosmos/cosmos-sdk/issues/10188) [PR cosmos-sdk#10189](https://github.com/cosmos/cosmos-sdk/pull/10189) that resulted from exactly this non-deterministic iteration. To ensure determinism, we only permit an iteration
to retrieve the map keys and then those keys can then be sorted, so instead of
```go
for k, v := range m {
    // Do something with key and value.
    _, _ = k, v
}
```

the requested pattern is instead
```go
keys := make([]string, 0, len(m))
for k := range m {
    keys = append(keys, k)
}
sort.Strings(keys)

for _, key := range keys {
    // Use the value.
    _ = m[key]
}
```
