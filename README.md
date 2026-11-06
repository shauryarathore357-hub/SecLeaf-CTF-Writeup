# SecLeaf CTF — Combined Writeup

Author of the challenges: **5h1kh4r**. Flag formats: `SecLeaf{...}` and `FLOWTRIQ{...}` (the DDoS pcaps).

Every challenge below follows the same shape, so it helps to know it up front:

- **Reversing:** an ELF reads companion data files, validates headers and hashes, derives keys from a hash chain, runs a keyed transform on the input and compares it to a keyed target. The workflow that worked each time was: **port the check to Python → validate against the real binary (gdb) → invert it**.
- **Forensics:** a pcap hides the real signal among decoys. Classify the traffic first, then decode only what is anomalous.
- **Crypto:** a structural weakness (prime-power moduli, related nonces) removes the need for brute force.

## Summary

| # | Challenge | Category | Flag |
|---|---|---|---|
| 1 | sugar_glass | Reversing | `SecLeaf{gl455_h0ld5_4_53cr3t}` |
| 2 | dead_letter_office | Reversing | `SecLeaf{th3_p0st0ff1c3_h4s_4_d4rk_s1d3!}` |
| 3 | null_choir | Reversing (VM) | `SecLeaf{th3_ch01r_s1ng5_1n_5h4d0w_m4ch1n35!!!!!}` |
| 4 | signal.wav | Signal / forensics | `SecLeaf{R4d10_W4v35}` |
| 5 | Roots (Hensel + CRT) | Crypto | `SecLeaf{r00ts_gr0w_through_pr1me_p0w3rs}` |
| 6 | Eleven signatures (ECDSA nonces) | Crypto | `SecLeaf{4ff1n3_n0nc3s_b3nd_th3_curv3}` |
| 7 | reflected-storm.pcap | Network forensics | `FLOWTRIQ{10.0.55.200_5_reflectors}` |
| 8 | leafsync.pcap | Network forensics | `SecLeaf{dns_labels_hide_the_truth}` |
| 9 | blackroot_archive.pcap | Network forensics | `SecLeaf{exported_objects_reveal_the_archive_key}` |
| 10 | signal-and-noise.pcap | Network forensics | `FLOWTRIQ{icmp_pivot_172.16.80.99}` |
| 11 | suspicious_activity.pcap | Network forensics | `SecLeaf{D474_3xf1l_DN5}` |
| 12 | Hollow Creek (web) | Web | collected via `X-Drip` headers (see below) |
| 13 | blackout_protocol | Reversing | `SecLeaf{n01s3_1n_th3_w1r35_4nd_4ft3r1m4g3s!!!!!}` |

Not solved in this session: `classified_report.locked` (the RSA layer was handled but the custom S-box layer was not found) and the Redshift Schnorr challenge. Neither is included as a solution.

---

## 1. sugar_glass (Reversing)

**Recon.** The ELF reads one line of input and runs a custom check.

**Analysis.** The check has four parts:

- **Length:** the input must be exactly 29 bytes.
- **Index walk:** each step picks an input position from a running counter (starting at 5, adding 11 each time) modulo 29.
- **Running state:** the byte at that position is XORed with a table byte, then mixed through a rotate, XOR and add chain.
- **Comparison:** the result is compared against a second table in `.rodata`.

**Solve.** Every step produces exactly one input byte, so the check can be run backwards without brute force. I wrote the inverse in Python and confirmed my port of the check accepted the result.

**Flag:** `SecLeaf{gl455_h0ld5_4_53cr3t}`

> Note: this one was verified against my Python port of the check, not by running the original binary. Run `./sugar_glass` once as a final confirmation.

## 2. dead_letter_office (Reversing)

**Recon.** The binary needs `postcard.grid` in its working directory. It prints "Delivered." on success and "Returned to sender." otherwise.

**Analysis.**

- **File check:** `postcard.grid` has an `HPL2` header holding the flag length (40), a pair count (20), an FNV-1a hash of the body and a seed. The body is a table of 20 entries.
- **Input check:** the input is processed two bytes at a time. Each pair goes through a 14-round mixing chain keyed by 8 bytes derived from `.rodata`, and the result is compared to table entries chosen by a running index.

**Solve.** The running state depends only on the file, never on the input, so each pair is an independent two-byte puzzle. I ported the loop to Python and brute-forced all 65,536 candidates per pair. Every pair had exactly one solution.

**Verify.** Running the original binary with the file in place printed "Delivered."

**Flag:** `SecLeaf{th3_p0st0ff1c3_h4s_4_d4rk_s1d3!}`

## 3. null_choir (Reversing, custom VM)

**Recon.** Three files: the binary, `echoes.trace` and `canticle.score`. The binary prints "Harmony." on success.

**Analysis.**

- **Keys:** the score's header gives a tag. The trace is filtered for 32 valid, checksummed records carrying that tag, one per slot, skipping decoys. These are mixed into a master seed.
- **Program:** the score holds three banks of 4096 encrypted 16-byte VM instructions. The seed picks the bank, shuffles the instruction order with a Feistel permutation and supplies the per-instruction keystream. The opcodes are also seed-dependent.
- **Opcodes:** there are 24, including two that only appear as mid-instruction jump-table entries. They operate on six 64-bit registers that hold the 48 input bytes. Every 64 instructions an extra mixing round runs.
- **Check:** after 4096 instructions the final register bytes must equal a seed-keyed target stored in the score header.

**Solve.** The program doesn't depend on the input and every instruction is invertible. I decoded all 4096 instructions and ran them in reverse from the target state. Before inverting, I checked the forward port against the real binary in gdb (seed, all six registers and the success flag all matched).

**Flag:** `SecLeaf{th3_ch01r_s1ng5_1n_5h4d0w_m4ch1n35!!!!!}`

## 4. signal.wav (Signal analysis)

**Challenge.** An unauthorized broadcast, AFSK at 1200 baud. Demodulate and recover the message.

**Recon.** The first 30 seconds are pure white noise with no signal in them. The real transmission is a loud, hard-clipped burst of about 0.18 s at the very end of the file, so isolating it by amplitude is enough; no band-pass filter is needed.

**Demodulation.**

- Zero-crossing analysis shows clean Bell 202 AFSK, with mark at 1200 Hz and space at 2200 Hz.
- Demodulating at 1200 baud gives 213 bits.
- Decoding as 8N1 serial (start bit, 8 data bits LSB first, stop bit) gives 21 bytes: the flag followed by a newline.
- Other framings (raw bits, NRZI, inverted polarity, MSB-first) produced only garbage.

**Flag:** `SecLeaf{R4d10_W4v35}`

## 5. Roots (Crypto: Hensel lifting + CRT)

**Challenge.** "Finding your roots." `chall.py` and `data.json` give two squares and an AES-GCM blob. The AES key comes from a 128-bit seed.

**Solve.**

1. The first square has 4 square roots modulo 2^72. The second has 2 roots modulo 3^51. Find each set by **Hensel lifting** from the roots mod 2 and mod 3, one prime-power step at a time.
2. Combine with CRT to get 8 candidate seeds modulo 2^72·3^51 (about 2^152.8). The real seed is only 128 bits, so each candidate needs just a few lifts.
3. Try each candidate as an AES-GCM key. Only one passes the authentication tag: seed `282779946134366997745983790016833981964`.

**Flag:** `SecLeaf{r00ts_gr0w_through_pr1me_p0w3rs}`

## 6. Eleven signatures (Crypto: ECDSA with related nonces)

**Challenge.** Eleven ECDSA signatures with "eleven different nonces" and an encrypted blob.

**Key idea.** Each signature makes its nonce a linear function of the private key `d`:
`k_i = (h_i + r_i·d) / s_i`.

The nonces in a window of five are related by a recurrence, so consecutive differences satisfy `Δ_{i+1} = A·Δ_i`. That gives `Δ₁² = Δ₀Δ₂` and `Δ₂² = Δ₁Δ₃`: two quadratics in `d` alone, and the unknown constants and nonces drop out.

**Solve.**

1. Compute the polynomial GCD of the two quadratics over GF(N) for all 7 possible window starts.
2. Only the window starting at record 3 produces a degree-1 GCD. That yields `d = 0xf833e0b4…4616de`.
3. The key decrypts the AES-GCM blob and passes its authentication tag.

**Flag:** `SecLeaf{4ff1n3_n0nc3s_b3nd_th3_curv3}`

## 7. reflected-storm.pcap (DDoS: DNS amplification)

**Flag format:** `FLOWTRIQ{<victim_ip>_<N>_reflectors}`

**Findings.**

- **Victim:** `10.0.55.200` received 600 DNS responses of 1014 bytes each (about 608 KB, most of the capture's bytes).
- **Spoofed queries:** the same address is the source of 600 small queries (75 bytes) for `ANY` records of `openresolver-test.example.com`. That is roughly 13.5× amplification.
- **Reflectors:** five open resolvers: `198.51.100.22`, `198.51.100.10`, `192.0.2.17`, `203.0.113.88`, `203.0.113.5`. Each sent back 110–133 responses.
- **Background:** the remaining 140 packets are small ordinary lookups between `10.0.1.50` and `10.0.1.1`, not part of the attack.

**Flag:** `FLOWTRIQ{10.0.55.200_5_reflectors}`

## 8. leafsync.pcap (DNS exfiltration)

**Story.** A developer workstation downloaded a "synchronization helper".

**Findings.**

- `10.20.30.15` fetched `leafsync-helper.sh` from `docs.internal.local`. The script is harmless on its face (it only echoes "LeafSync helper started").
- About a second later it sent six DNS queries to the unfamiliar domain `sync-cache.training.local`, with names like `01.U2VjTGVh.sync-cache.training.local`. Each carries a sequence number and a base64 chunk. The other 18 queries are ordinary lookups.

**Decode.** Join the chunks in sequence order: `U2VjTGVh` + `ZntkbnNf` + `bGFiZWxz` + `X2hpZGVf` + `dGhlX3Ry` + `dXRofQ==`, then base64-decode.

**Flag:** `SecLeaf{dns_labels_hide_the_truth}`

## 9. blackroot_archive.pcap (HTTP + SMTP + TCP stream)

**Findings.**

- **Manifest:** `10.88.12.15` downloaded `ledger-sync.manifest.b64` over HTTP from `docs.blackroot.internal`. The body is split across TCP segments; reassembled and base64-decoded it says `encoding=base64`, `key_source=mail:archive-notice`, `next_service=tcp/4711`.
- **Key:** the SMTP archive notice to `operations@blackroot.internal` contains `Recovery key: rootleaf`.
- **Decoys:** exchanges with `198.51.100.144` on ports 4700–4703 (`HELLO … status=healthy`) and UDP CPU metrics to port 9000 carry nothing.
- **Data:** only the port 4711 stream carries data: ten `record=NN;blob=…` lines followed by `commit=true`.

**Decrypt.** Concatenate the ten blobs in record order, XOR with `rootleaf` repeating, and base64-decode the result.

**Flag:** `SecLeaf{exported_objects_reveal_the_archive_key}`

## 10. signal-and-noise.pcap (multi-vector DDoS)

**Flag format:** `FLOWTRIQ{decoy_pivot_<pivot_ip>}`. I followed the example's underscore placement, which gave `icmp_pivot_<ip>`.

The victim is `10.0.88.10`. Three vectors:

| Vector | What it looks like | Verdict |
|---|---|---|
| **ICMP echo** | 800 pings, all 84 bytes with zero-filled payloads, from 50 hosts in `10.99.0.0/24`. Flat rate of about 7 packets per second (≈4.5 kbps) for two minutes. | **Decoy.** No ramp, no amplification, no payload, and none of those IPs appear in another vector. Highest packet count but negligible bandwidth. |
| **DNS amplification** | 350 spoofed `ANY big-record.example.org` queries (68 bytes) to four reflectors `198.18.0.{11,22,33,44}`, returning 714-byte responses (about 10.5× amplification, roughly 250 KB at the victim). | Real. |
| **TCP SYN flood (443)** | 500 SYNs from 41 hosts in `172.16.80.0/24`, never answered with a SYN-ACK. The 60 SYNs from `10.0.1.x` complete normal handshakes. | Real. |

**Pivot.** `172.16.80.99` is the top SYN flood source (29 SYNs between about 15 s and 73 s). From about 60 s it also sends 31 `ANY` queries, with its own address as source, to the same four reflectors. That overlap makes it the node coordinating the DNS amplification.

**Flag:** `FLOWTRIQ{icmp_pivot_172.16.80.99}`

## 11. suspicious_activity.pcap (DNS exfiltration, subtle)

**Recon.** 1038 packets, 960 of them TCP on port 443 (normal-looking browsing the attacker hid behind). The other 78 are 39 DNS queries with responses. 35 are ordinary lookups (cloudflare, microsoft, github, ubuntu, google); four go to `evil.com`, all from `192.168.1.20`, each with a base64 chunk as its subdomain label:

| Time | Query |
|---|---|
| 2.40 s | `U2VjTGVhZn.evil.com` |
| 4.16 s | `tENDc0XzN4.evil.com` |
| 5.49 s | `ZjFsX0RONX.evil.com` |
| 6.91 s | `0=.evil.com` |

**Decode.** Join in time order: `U2VjTGVhZntENDc0XzN4ZjFsX0RONX0=` → base64 → flag. The responses just echo the name with the same A record, so data only travels outbound in the query names.

**Flag:** `SecLeaf{D474_3xf1l_DN5}` (malicious domain: `evil.com`)

## 12. Hollow Creek Water Authority (Web)

**Challenge.** The Main 07 status page keeps losing "pressure", and the incident log mentions a work order. Flag format `SecLeaf{...}`.

**Recon.** The sandbox couldn't reach the challenge host, so I probed from the user's machine with a script. A probe of two refreshes in one session showed the leak: each response carries one character in the `X-Drip` header and its position in `X-Drip-Serial`, formatted `n/40` (for example `S` as 1/40 and `1` as 37/40). A `work_order` cookie advances with each refresh, so a **single persistent session** is required; a fresh session per request only ever returns the first character.

**Solve.** Refresh with one session until all 40 serials are collected, then sort by serial and join.

```python
import requests
s = requests.Session()                  # keep the work_order cookie
drops, total = {}, None
while total is None or len(drops) < total:
    r = s.get("http://web.secleaf.xyz:8080")
    n, total = map(int, r.headers["X-Drip-Serial"].split("/"))
    drops[n] = r.headers["X-Drip"]
print("".join(drops[k] for k in sorted(drops)))
```

The flag is the 40-character assembled string. I never saw the final output from the real site in this session, so it's not reproduced here.

## 13. blackout_protocol (Reversing, three evidence files)

**Files.** `blackout_protocol` (ELF), `transmission.pcap`, `retained.mem`, `incident.journal`. The binary prints `Authenticated.` on success.

**Analysis.** The binary builds its keys from all three evidence files:

1. **Memory dump:** check the header and tag (`mem+0x184`).
2. **Journal:** keep only records with the right tag and a valid FNV-1a checksum, giving a table of 48 qwords.
3. **Chain hash:** fold the table through a chain of `mix64` steps (a splitmix64-style mixer) into one hash `H`.
4. **pcap:** pull the UDP packets from `10.64.0.1:2419` to `10.64.0.2:31337`. Each is a `BKP5` record with a tag and a slot byte; 32 valid slots, each validated by two checksums, are recovered and the 12-byte chunks decrypted into a 384-byte buffer.
5. **S-box:** build a byte substitution table with Fisher–Yates driven by xorshift64*, seeded from the tag, `H` and the recovered buffer.
6. **Transform:** run a 52-round keyed substitution / permutation / rotate network over the 48-byte input.
7. **Compare:** the result must equal a keyed target built from `retained.mem` (bytes at `0x600 + ((i*0x89+0x3b) & 0x1ff)` XORed with a keystream).

**Solve.**

1. Port steps 1–6 to Python, then check the intermediate values.
2. Invert each round in reverse order. All round operations (substitution, permutation, rotation, running XOR/add) are invertible.
3. Feed the keyed target through the inverse to get the 48-byte input.
4. Check that my forward port on the result reproduces the target, then run the real binary.

```
$ ./blackout_protocol   # input: recovered flag
Authenticated.
```

**Flag:** `SecLeaf{n01s3_1n_th3_w1r35_4nd_4ft3r1m4g3s!!!!!}`

---

## Takeaways

- **Do the data work before the clever work.** In every pcap challenge, a counting pass over protocols, bytes and sources showed which traffic was a decoy before any decoding.
- **Port, validate, invert.** Whenever a binary's transform doesn't depend on the input (the postcard, the VM, the 52-round network), the cheapest solve is to port it, confirm it against the real binary and run it backwards.
- **Structure beats brute force.** Prime-power roots and affine nonce relations both reduce to small algebra problems.
- **Read the headers.** The web challenge's leak was in response headers, not the page body.
