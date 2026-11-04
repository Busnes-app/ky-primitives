// Package password hashes and verifies passwords with Argon2id.
//
// The suite ran three algorithms and five parameter sets: Argon2id at t=1 in
// ky_server_base and gridlock-server, at t=3 in kysignon-server, kyrecovery-server and
// kydns-server (p=2 there, p=4 elsewhere), and scrypt at N=2^17 in kynotes-server and
// kypost-server and N=2^15 in kybookmarks-server. The Argon2 encodings are mutually
// parseable, so a hash minted at t=1 verified in a t=3 product at a third of the intended
// attacker cost and nothing flagged it.
//
// This package is the suite's one answer: RFC 9106's second recommended profile, 64 MiB
// at t=3 p=4, self-describing in PHC form.
//
// It is the only package in this module with a dependency. Argon2 is not in the standard
// library and is not on a proposal track, so the module's rule bends exactly once, here,
// and TestModuleDependenciesAreAllowlisted holds the line at x/crypto.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// Params are the Argon2id cost parameters. Memory is in KiB.
type Params struct {
	Memory  uint32
	Time    uint32
	Threads uint8
}

// DefaultParams returns RFC 9106's second recommended option. The first asks for 2 GiB,
// which no login endpoint can afford per request.
//
// A function rather than a variable: an exported var is global policy any importer can
// assign to, and a configuration reload writing it while a login reads it is a data race
// that also lets two concurrent hashes use different parameters. Callers wanting other
// costs pass a Params to a call, they do not edit everyone else's.
func DefaultParams() Params {
	return Params{Memory: defaultMemory, Time: defaultTime, Threads: defaultThreads}
}

const (
	defaultMemory  = 64 * 1024
	defaultTime    = 3
	defaultThreads = 4
)

const (
	saltBytes = 16
	keyBytes  = 32
	version   = argon2.Version // 19

	// Bounds on what a stored hash may ask for. A stored hash is attacker-controlled
	// wherever the store is, and one asking for terabytes OOM-kills the process on the
	// next login rather than failing that login.
	minMemory  = 8 * 1024
	maxMemory  = 256 * 1024
	minTime    = 1
	maxTime    = 10
	minThreads = 1
	maxThreads = 16
	minSalt    = 8
	minKey     = 16
	maxDecoded = 1024
)

var (
	// ErrBusy reports that too many derivations are already running. Callers should
	// answer 503 and must not spend a lockout strike: this is the server saying "not
	// now", not the user getting the password wrong.
	ErrBusy = errors.New("password: too many concurrent derivations")
	// ErrMalformed reports a stored hash that is not a well-formed Argon2id PHC string.
	// It is never treated as a verification failure against default parameters.
	ErrMalformed = errors.New("password: stored hash is not a valid argon2id PHC string")
)

// ponytail: fixed budgets and wait. Make them configurable if a deployment needs a
// different ceiling.
const (
	// budgetKiB is the total memory all concurrent request-driven derivations may
	// reserve, equal to four derivations at the default 64 MiB. One exception: the
	// once-per-process dummy mint in dummyHash bypasses this budget entirely, so the
	// process can transiently run one 64 MiB derivation beyond it — once, ever. See
	// dummyHash for why.
	//
	// It is a byte budget rather than a slot count because slots bound how many
	// derivations run, not how large they are, and Verify accepts a stored hash asking
	// for anything up to maxMemory. Four slots therefore admitted 4 x 256 MiB while this
	// comment claimed 256 MiB. Reserving p.Memory makes the number here the number
	// enforced.
	budgetKiB = 4 * 64 * 1024

	// budgetLanes is the same four derivations counted in Argon2 lanes.
	//
	// Memory alone was not admission control. A stored hash at the 8 MiB floor reserves a
	// thirty-second of the byte budget, so 32 of them run at once, and each may ask for
	// maxThreads lanes and maxTime iterations: 512 lanes on a machine with a handful of
	// cores, all of it under the advertised memory ceiling. CPU was written off as
	// degrading rather than killing, which is true of one derivation and false of the
	// fleet a byte budget admits — and Verify takes these parameters from the stored hash,
	// so whoever can write the store chooses them.
	budgetLanes = 4 * defaultThreads

	maxWait = 2 * time.Second
)

// MaxMemoryKiB and MaxLanes are the two dimensions of this package's derivation budget,
// taken together under one acquirer so two waiters can never each hold part of what the
// other needs. They are exported so a product running derive as well can add the two
// budgets up rather than assume one of them is the whole story. Memory is in KiB, matching
// Params.Memory and every other memory value in this package.
//
// Both are derived from unexported constants, which keeps them from drifting apart, but
// also keeps the number out of godoc for anyone reading pkg.go.dev rather than the source.
// Stated here so it doesn't have to be: MaxMemoryKiB is currently 262144 KiB (256 MiB);
// MaxLanes is currently 16.
const (
	MaxMemoryKiB = budgetKiB
	MaxLanes     = budgetLanes
)

// Two dimensions, one queue. Memory is what OOM-kills a process and lanes are what starve
// the scheduler; reserving them under the same serialised acquirer is what keeps two
// half-satisfied waiters from holding each other's remainder.
var budget = struct {
	admit     chan struct{} // capacity 1: one acquirer negotiates at a time
	wake      chan struct{} // poked on release
	mu        sync.Mutex
	free      int64
	peak      int64
	freeLanes int64
	peakL     int64
}{
	admit:     make(chan struct{}, 1),
	wake:      make(chan struct{}, 1),
	free:      budgetKiB,
	freeLanes: budgetLanes,
}

// withBudget runs fn holding a reservation of kib and lanes, or reports ErrBusy.
//
// Reservations are serialised through admit so that no two acquirers can each hold part of
// what the other needs, which is the deadlock a naive multi-token semaphore has. That
// argument is what lets a second dimension be added for free: both are taken under the
// same single acquirer, so there is still no pair of waiters holding each other's
// remainder. It also makes the queue first-come rather than letting small requests starve
// a large one. Only the reservation is serialised; the derivation itself runs outside the
// queue.
func withBudget(kib, lanes int64, fn func()) error {
	// Unsatisfiable however long we wait, so say so now rather than after maxWait.
	if kib > budgetKiB {
		return fmt.Errorf("%w: needs %d KiB, the whole budget is %d KiB", ErrBusy, kib, budgetKiB)
	}
	if lanes > budgetLanes {
		return fmt.Errorf("%w: needs %d lanes, the whole budget is %d", ErrBusy, lanes, budgetLanes)
	}
	timer := time.NewTimer(maxWait)
	defer timer.Stop()

	select {
	case budget.admit <- struct{}{}:
	case <-timer.C:
		return ErrBusy
	}
	admitted := true
	leaveQueue := func() {
		if admitted {
			admitted = false
			<-budget.admit
		}
	}
	defer leaveQueue()

	for {
		budget.mu.Lock()
		// Both or neither: taking memory while waiting for lanes would reintroduce the
		// partial hold the single queue exists to prevent.
		if budget.free >= kib && budget.freeLanes >= lanes {
			budget.free -= kib
			budget.freeLanes -= lanes
			if used := budgetKiB - budget.free; used > budget.peak {
				budget.peak = used
			}
			if used := budgetLanes - budget.freeLanes; used > budget.peakL {
				budget.peakL = used
			}
			budget.mu.Unlock()
			// Admit is the queue, not the reservation. Deriving while holding it capped
			// the package at one derivation at a time whatever the budget allowed, and
			// left the wait below unreachable.
			leaveQueue()
			defer release(kib, lanes)
			fn()
			return nil
		}
		budget.mu.Unlock()

		select {
		case <-budget.wake:
		case <-timer.C:
			return ErrBusy
		}
	}
}

// release returns a reservation and wakes whoever is queued behind it.
func release(kib, lanes int64) {
	budget.mu.Lock()
	budget.free += kib
	budget.freeLanes += lanes
	budget.mu.Unlock()
	select {
	case budget.wake <- struct{}{}:
	default:
	}
}

// peakReserved, inFlight and resetPeak exist for the budget test, which cannot observe a
// ceiling it has no way to measure.
func peakReserved() int64 {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	return budget.peak
}

func inFlight() int64 {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	return budgetKiB - budget.free
}

func peakLanes() int64 {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	return budget.peakL
}

func lanesInFlight() int64 {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	return budgetLanes - budget.freeLanes
}

func resetPeak() {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	budget.peak, budget.peakL = 0, 0
}

// Hash derives a PHC-encoded Argon2id hash at the current parameters.
func Hash(plaintext string) (string, error) {
	return hashWith(plaintext, DefaultParams())
}

const dummyPlaintext = "dummy verification plaintext"

// dummyHashMu guards dummyHashValue, a mutex-guarded memo rather than sync.OnceValue: a
// OnceValue that panics caches the panic and re-raises it on every later call forever. If
// dummyMint ever panics, the assignment below never completes, so dummyHashValue stays
// unset and the next call retries — nothing here caches a failure.
var (
	dummyHashMu    sync.Mutex
	dummyHashValue string
)

// dummyHash mints the dummy hash once, on first use, at the current parameters — so
// DummyVerify costs what a real verification costs even after those parameters move.
//
// Minted through dummyMint, which bypasses withBudget: this derivation runs once per
// process, not once per request, so it is not the concurrent load admission control exists
// to bound. Going through the budget meant a single transient ErrBusy on the first-ever
// call would be cached forever by sync.OnceValue, bricking DummyVerify — with no benefit,
// since one extra process-lifetime derivation was never what the budget needed to cap.
func dummyHash() string {
	dummyHashMu.Lock()
	defer dummyHashMu.Unlock()
	if dummyHashValue == "" {
		dummyHashValue = dummyMint()
	}
	return dummyHashValue
}

// DummyVerify spends the cost of a verification and reports nothing.
//
// A login that answers "no such account" faster than "wrong password" enumerates accounts.
// Call this on every reject path that did not reach a real Verify, so the two cost the
// same.
//
// It is not perfect and should not be sold as such: Verify can return ErrBusy without
// deriving anything, and that path is fast. Under load the oracle reopens. Shedding is
// still the right answer to overload — just do not describe this as constant time. The
// first call in a process additionally mints the dummy hash, so it costs roughly two
// derivations rather than one; every call after that costs one.
func DummyVerify() {
	_, _ = Verify(dummyPlaintext, dummyHash())
}

// HashWith derives a PHC-encoded Argon2id hash at the given parameters.
//
// Hash is the suite's answer and what production code should call. This exists for two
// callers: a test suite that cannot afford 64 MiB per derivation, and a product that must
// mint at parameters an existing deployment already uses. Parameters are bounded to the
// band Verify accepts, so this cannot mint a hash that verifies nowhere — but it can mint
// a weaker one than the suite standard, and that is the caller's responsibility.
func HashWith(plaintext string, p Params) (string, error) {
	return hashWith(plaintext, p)
}

func hashWith(plaintext string, p Params) (string, error) {
	if plaintext == "" {
		return "", errors.New("password: refusing to hash an empty password")
	}
	if err := p.Validate(); err != nil {
		return "", err
	}
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: %w", err)
	}
	var key []byte
	if err := withBudget(int64(p.Memory), int64(p.Threads), func() {
		key = argon2.IDKey([]byte(plaintext), salt, p.Time, p.Memory, p.Threads, keyBytes)
	}); err != nil {
		return "", err
	}
	return encode(p, salt, key), nil
}

// dummyMint derives the dummy hash at the current default parameters without acquiring the
// budget. See dummyHash for why: this runs once per process, not once per request.
//
// No error return: crypto/rand.Read cannot produce a non-nil error on this module's Go
// floor (1.26.6) without already having crashed the process via runtime.fatal (broken
// entropy source, since Go 1.24) — there is no error state left for a caller to handle.
func dummyMint() string {
	p := DefaultParams()
	salt := make([]byte, saltBytes)
	_, _ = rand.Read(salt)
	key := argon2.IDKey([]byte(dummyPlaintext), salt, p.Time, p.Memory, p.Threads, keyBytes)
	return encode(p, salt, key)
}

// encode renders the PHC string for a derived key at p.
func encode(p Params, salt, key []byte) string {
	return "$argon2id$" + versionSegment + "$" + p.segment() + "$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(key)
}

// Verify reports whether plaintext produced encoded. A malformed or out-of-bounds stored
// hash is an error, never a silent fall back to the compiled defaults.
func Verify(plaintext, encoded string) (bool, error) {
	p, salt, want, err := parse(encoded)
	if err != nil {
		return false, err
	}
	var got []byte
	if err := withBudget(int64(p.Memory), int64(p.Threads), func() {
		got = argon2.IDKey([]byte(plaintext), salt, p.Time, p.Memory, p.Threads, uint32(len(want)))
	}); err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// NeedsRehash reports whether a stored hash was made below the current parameters, so a
// deployment can upgrade it on the next successful login.
//
// A hash this package did not write — malformed, foreign, or otherwise unparseable — is not
// stale, it is not ours: this reports false rather than guessing. Verify still refuses a
// foreign hash outright.
//
// The error return is currently always nil. It is kept for signature stability: several
// migration plans are already written against (bool, error).
func NeedsRehash(encoded string) (bool, error) {
	p, _, _, err := parse(encoded)
	if err != nil {
		// A hash this package did not write is not stale — it is not ours. Rehashing on a
		// guess is how a product ends up re-minting a format it cannot read. Verify still
		// refuses it outright; that is where a malformed hash must be an error.
		return false, nil
	}
	d := DefaultParams()
	return p.Memory < d.Memory || p.Time < d.Time || p.Threads != d.Threads, nil
}

// versionSegment is the only version segment this package accepts or emits.
var versionSegment = "v=" + strconv.Itoa(version)

// parseParams reads "m=<n>,t=<n>,p=<n>" and nothing else.
//
// Every field is parsed with strconv, then the whole segment is re-encoded and compared
// to the input. That one comparison is what rejects trailing garbage, a fourth field,
// reordering, leading zeros, a leading plus and surrounding space, without a rule for
// each: a stored hash either spells its parameters the way this package spells them or it
// is not a hash this package wrote.
func parseParams(segment string) (Params, error) {
	fields := strings.Split(segment, ",")
	if len(fields) != 3 {
		return Params{}, fmt.Errorf("%w: parameter segment %q has %d fields, want 3", ErrMalformed, segment, len(fields))
	}
	var values [3]uint64
	for i, prefix := range [3]string{"m=", "t=", "p="} {
		if !strings.HasPrefix(fields[i], prefix) {
			return Params{}, fmt.Errorf("%w: parameter %d is %q, want a %q field", ErrMalformed, i, fields[i], prefix)
		}
		v, err := strconv.ParseUint(strings.TrimPrefix(fields[i], prefix), 10, 32)
		if err != nil {
			return Params{}, fmt.Errorf("%w: parameter %q: %v", ErrMalformed, fields[i], err)
		}
		values[i] = v
	}
	if values[2] > 255 {
		return Params{}, fmt.Errorf("%w: threads %d does not fit a uint8", ErrMalformed, values[2])
	}
	p := Params{Memory: uint32(values[0]), Time: uint32(values[1]), Threads: uint8(values[2])}
	if canonical := p.segment(); canonical != segment {
		return Params{}, fmt.Errorf("%w: parameter segment %q is not canonical, want %q", ErrMalformed, segment, canonical)
	}
	return p, p.Validate()
}

// segment renders the canonical parameter spelling.
func (p Params) segment() string {
	return fmt.Sprintf("m=%d,t=%d,p=%d", p.Memory, p.Time, p.Threads)
}

// Validate reports whether these parameters are inside the band a stored hash may carry.
//
// The band is parse's, not a second opinion: minting something Verify would refuse is a
// hash that works nowhere, which is a worse failure than being told no.
func (p Params) Validate() error {
	switch {
	case p.Memory < minMemory || p.Memory > maxMemory:
		return fmt.Errorf("%w: memory %d KiB is outside %d-%d", ErrMalformed, p.Memory, minMemory, maxMemory)
	case p.Time < minTime || p.Time > maxTime:
		return fmt.Errorf("%w: time %d is outside %d-%d", ErrMalformed, p.Time, minTime, maxTime)
	case p.Threads < minThreads || p.Threads > maxThreads:
		return fmt.Errorf("%w: threads %d is outside %d-%d", ErrMalformed, p.Threads, minThreads, maxThreads)
	}
	return nil
}

// parse reads a PHC string strictly: every segment must be present and well formed.
func parse(encoded string) (Params, []byte, []byte, error) {
	// SplitN, so a stored hash made of separators cannot allocate a slice per byte.
	parts := strings.SplitN(encoded, "$", 7)
	if len(parts) != 6 || parts[0] != "" {
		return Params{}, nil, nil, fmt.Errorf("%w: %d segments", ErrMalformed, len(parts))
	}
	if parts[1] != "argon2id" {
		return Params{}, nil, nil, fmt.Errorf("%w: algorithm %q", ErrMalformed, parts[1])
	}

	// Exact string comparison rather than a scan: fmt.Sscanf reads the fields it is
	// asked for and ignores whatever follows, so "v=19GARBAGE" and "m=...,p=04" both
	// parsed clean. A stored hash has exactly one canonical spelling.
	if parts[2] != versionSegment {
		return Params{}, nil, nil, fmt.Errorf("%w: version segment %q, want %q", ErrMalformed, parts[2], versionSegment)
	}

	p, err := parseParams(parts[3])
	if err != nil {
		return Params{}, nil, nil, err
	}

	salt, err := decode(parts[4], minSalt)
	if err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: salt: %v", ErrMalformed, err)
	}
	key, err := decode(parts[5], minKey)
	if err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: hash: %v", ErrMalformed, err)
	}
	return p, salt, key, nil
}

func decode(s string, min int) ([]byte, error) {
	if len(s) > base64.RawStdEncoding.EncodedLen(maxDecoded) {
		return nil, fmt.Errorf("%d encoded bytes, want at most %d", len(s), base64.RawStdEncoding.EncodedLen(maxDecoded))
	}
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) < min || len(b) > maxDecoded {
		return nil, fmt.Errorf("%d bytes, want %d-%d", len(b), min, maxDecoded)
	}
	return b, nil
}
