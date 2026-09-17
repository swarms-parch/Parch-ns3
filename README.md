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

The authentication phase follows the message sequence:

```text
CH  -> GCS : M0
GCS -> CH  : M1
CH  -> GCS : M2
```

After successful verification of `M2`, the GCS and CH complete mutual authentication and update the rolling authentication state.

## Failure-Resilient ACC Handover

The handover is performed after `ACC_old` becomes unavailable.

```text
ACC_new -> CH      : M3
CH      -> ACC_new : M4
```

The CH authenticates `ACC_new`, while `ACC_new` verifies the CH and the key-confirmation value. A fresh CH-ACC_new session is then established without requiring participation of `ACC_old`.

## Network-Level Evaluation

The NS-3 implementation also provides:

- End-to-end GCS-CH authentication latency
- GCS-CH authentication throughput
- End-to-end ACC handover latency
- ACC handover throughput

Authentication latency is obtained from the transmission of `M0` until successful completion of `M2`.

Handover latency is obtained from the transmission of `M3` until successful verification of `M4` by `ACC_new`.

Throughput is calculated using the successfully received protocol bytes over the corresponding protocol completion interval.

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

A successful execution performs the complete GCS-CH authentication followed by failure-resilient handover to `ACC_new`.

The screenshots `ns-sim-1.png` and `ns-sim-2.png` show the corresponding NS-3 execution output.