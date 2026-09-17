PARCH NS-3 Functional Validation



This repository contains the NS-3 implementation of the PARCH GCS–CH authentication and failure-resilient ACC handover protocols.



\## Files



\- `parch\_protocol.cc` — NS-3 implementation of PARCH

\- `ns-sim.png` — successful functional-validation output

\- `README.md` — repository documentation



\## Configuration



The implementation uses:



\- 1024 WOTS+ credentials

\- 10 enrolled CH roots

\- PUF bit-error rate of 0.001

\- Four independent NS-3 nodes:

&#x20; - GCS

&#x20; - CH

&#x20; - ACC\_old

&#x20; - ACC\_new



Each entity operates as an independent NS-3 node with its own UDP socket.



\## Network Configuration



| Entity | IPv4 Address |

|---|---|

| GCS | `10.1.1.1` |

| CH | `10.1.1.2` |

| ACC\_old | `10.1.1.3` |

| ACC\_new | `10.1.1.4` |



\## Protocol Sequence



\### GCS–CH Authentication



The implemented authentication flow is:



```text

CH  -> GCS : M0

GCS -> CH  : M1

CH  -> GCS : M2

```



After successful mutual authentication, the rolling GCS–CH authentication state is updated.



\### Failure-Resilient ACC Handover



After the active ACC becomes unavailable, the handover flow is:



```text

ACC\_new -> CH      : M3

CH      -> ACC\_new : M4

```



The CH authenticates `ACC\_new`, while `ACC\_new` authenticates the CH and verifies explicit key confirmation. A fresh CH–ACC\_new session is established without participation of `ACC\_old`.



\## Running the Implementation



Place `parch\_protocol.cc` under:



```text

ns-3-dev/scratch/parch/

```



From the NS-3 root directory:



```bash

cd \~/ns-3-dev

```



Configure NS-3:



```bash

./ns3 configure

```



Build the PARCH implementation:



```bash

cmake --build cmake-cache --target scratch\_parch\_parch\_protocol -j$(nproc)

```



Run the generated executable:



```bash

./cmake-cache/scratch/parch/scratch/parch/ns3-dev-parch\_protocol-default

```



To explicitly run with the paper configuration:



```bash

./cmake-cache/scratch/parch/scratch/parch/ns3-dev-parch\_protocol-default \\

&#x20; --credentialCount=1024 \\

&#x20; --enrolledChCount=10 \\

&#x20; --pufBitErrorRate=0.001

```





The execution screenshot is provided in `ns-sim.png`.

