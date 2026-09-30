# PARCH NS-3 Implementation

This repository contains the NS-3 implementation of the PARCH GCS-CH authentication and failure-resilient ACC handover protocols.

The implementation is used to check the working of both protocol phases in a simulated UAV network. It also provides end-to-end latency and throughput for the authentication and handover procedures.

## Files

- `parch_protocol.cc` - NS-3 implementation of the PARCH protocol
- `ns-sim-1.png` - NS-3 execution output
- `ns-sim-2.png` - NS-3 execution output
- `README.md` - instructions for running the implementation

## Simulation Setup

The simulation contains four separate NS-3 nodes:

| Entity | IP Address |
|---|---|
| GCS | `10.1.1.1` |
| CH | `10.1.1.2` |
| ACC_old | `10.1.1.3` |
| ACC_new | `10.1.1.4` |

Each entity uses its own UDP socket.

The configuration used in the implementation is:

- WOTS+ credentials: `m = 1024`
- Number of enrolled CH roots: `n = 10`
- PUF bit-error rate: `0.001`

## GCS-CH Authentication

The current PARCH authentication phase uses two online messages:

```text
GCS -> CH  : M1
CH  -> GCS : M2
```

Before the online exchange, the GCS and CH hold the rolling authentication state established during enrollment.

For `M1`, the GCS generates a fresh random value `Q` and a new PUF challenge. The current PUF-derived response is used to mask `Q`, while the authentication hash binds the current response, `Q`, the current and new challenges, and the current CH pseudonym.

After verifying `M1`, the CH generates the next PUF/fuzzy-extractor state and derives the session key and next pseudonym from a 36-byte BLAKE2b output. The CH then sends `M2`, which carries the current pseudonym, the masked new PUF-derived response, and the authentication hash.

After successful verification of `M2`, the GCS and CH complete mutual authentication and update the rolling authentication state. The CH temporarily retains its previous authentication state to support recovery if `M2` is lost.

## Failure-Resilient ACC Handover

The handover is performed after `ACC_old` becomes unavailable.

```text
ACC_new -> CH      : M3
CH      -> ACC_new : M4
```

The CH authenticates `ACC_new` using its enrolled WOTS+ credential and Merkle verification. The CH then regenerates its PUF-derived one-time WOTS+ credential, performs ML-KEM encapsulation, and sends `M4`.

`ACC_new` verifies the CH credential through the Merkle paths, decapsulates the ML-KEM ciphertext, derives the fresh pairwise session key, and verifies the HMAC-based key-confirmation value. A fresh CH-ACC_new session is therefore established without participation of `ACC_old`.

## Network-Level Evaluation

The NS-3 implementation provides:

- End-to-end GCS-CH authentication latency
- GCS-CH authentication throughput
- End-to-end ACC handover latency
- ACC handover throughput

Authentication latency is measured from transmission of `M1` by the GCS until successful verification of `M2` by the GCS.

Handover latency is measured from transmission of `M3` by `ACC_new` until successful verification of `M4` by `ACC_new`.

Throughput is calculated using the successfully received protocol bytes over the corresponding protocol completion interval.

The NS-3 simulation time does not include the host CPU execution time of the cryptographic primitives. The primitive computation times reported in the paper are obtained separately from Raspberry Pi 5 benchmarks.

## Running the Code

Copy `parch_protocol.cc` into the PARCH scratch directory of NS-3:

```text
ns-3-dev/scratch/parch/
```

Go to the NS-3 directory:

```bash
cd ~/ns-3-dev
```

Configure NS-3:

```bash
./ns3 configure
```

Build the PARCH program:

```bash
cmake --build cmake-cache --target scratch_parch_parch_protocol -j$(nproc)
```

Run the program:

```bash
./cmake-cache/scratch/parch/scratch/parch/ns3-dev-parch_protocol-default
```

The parameters used in the paper can be explicitly supplied as:

```bash
./cmake-cache/scratch/parch/scratch/parch/ns3-dev-parch_protocol-default \
  --credentialCount=1024 \
  --enrolledChCount=10 \
  --pufBitErrorRate=0.001
```

A successful execution performs the GCS-CH mutual authentication followed by failure-resilient handover to `ACC_new`.

The screenshots `ns-sim-1.png` and `ns-sim-2.png` show the corresponding NS-3 execution output, including protocol execution, end-to-end latency, and application throughput.
