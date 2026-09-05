# Anchr — Full Build Handoff

**Project:** Anchr — Zero-Knowledge Legal Vault  
**Hackathon:** BLI Legal Tech Hackathon  
**Repo:** https://github.com/geekman58748/anchr  
**Live:** https://anchr-60kj.onrender.com/  
**Date:** September 4–5, 2026  
**Author:** geekman58748  

---

## 1. Product Vision

Anchr is a **zero-knowledge, client-side encryption vault** for sensitive legal documents. Instead of storing files on-chain (which blows up gas costs), it:

1. **Encrypts** PDFs, NDAs, and audit logs entirely in the browser (AES-256)
2. **Generates** a 32-byte Merkle root from the encrypted content
3. **Posts** only the hash to the blockchain for immutable timestamping / chain-of-custody
4. **Crypto-shreds** by destroying the decryption key for instant GDPR compliance wipes

**Tagline:** *"Seal. Prove. Shred."*

**Product Name:** **Anchr** — vowel-dropped "Anchor" for startup aesthetic. One syllable, 5 letters. Works as a verb: *"Anchr this document."*

---

## 2. Competitive Positioning

This is NOT a "file upload" tool. It's **infrastructure for legal compliance**. The crypto-shredding angle maps cleanly to GDPR right-to-erasure and data retention policies. Merkle root timestamping = immutable evidence of document existence without exposing content.

**What makes it win against typical legal tech hacks:**
- Most legal tech hacks are "AI contract review" clones — this is infrastructure
- Jurisdiction-agnostic — works across legal systems
- Demoable flow: encrypt → Merkle root → on-chain → shred
- Clear B2B buyer: law firms, compliance teams, corporate legal departments

---

## 3. Core Concept: Blockchain TOTP Authenticator

### The Idea
Instead of traditional Google Authenticator (TOTP with a centralized server DB), Anchr would use a **blockchain-based authenticator** — a smart contract that stores a commitment hash (`H(secret)`) on-chain and verifies TOTP codes against it.

### How Traditional TOTP Works (Google Authenticator)
```
Shared Secret (stored in SERVER DB)
        │
        ▼
┌──────────────┐     ┌──────────────┐
│  Your Phone  │     │   Server DB  │
│  HMAC + Time │────▶│  HMAC + Time │
│  = 482901    │     │  = 482901    │
│              │     │  Match? ✓    │
└──────────────┘     └──────────────┘
```
**Vulnerability:** The shared secret lives in a centralized database. If that DB is breached, every user's TOTP is compromised. The server can also be compelled by court order, rogue admin, or hack.

### Anchr's Blockchain TOTP
```
Shared Secret (commitment hash on-chain)
        │
        ▼
┌──────────────┐     ┌──────────────────┐
│  Your Phone  │     │  Smart Contract  │
│  HMAC + Time │────▶│  Verify(proof)   │
│  = 482901    │     │  Block timestamp │
│              │     │  Match? ✓        │
└──────────────┘     └──────────────────┘
```
**Difference:** No centralized DB. Verification logic is a smart contract — immutable, auditable, no rogue admin.

### Security Comparison

| Attack Vector | Google Auth | Anchr Blockchain Auth |
|---|---|---|
| DB breach | Secret exposed → all codes compromised | No DB to breach |
| Rogue admin | Can approve unauthorized access | Contract logic is immutable — no admin override |
| Court order | Server can be compelled to verify | Censorship-resistant — no single entity controls it |
| Trust model | Trust Google + the server | Trust math + the chain |
| Auditability | Closed source, opaque | Contract is public, verifiable by anyone |
| Single point of failure | The server | The chain (distributed) |

### Implementation: Commit-Reveal Pattern

**SETUP (one-time):**
1. User generates TOTP secret on device
2. Contract stores `H(secret)` as commitment
3. Secret never leaves the device

**LOGIN:**
1. User's device generates TOTP code
2. Client-side: verify code against `H(secret)` stored on-chain
3. If match → generate a signed session proof
4. Server trusts the proof because it's signed by the on-chain commitment

**KEY INSIGHT:** Don't verify on-chain in real-time. Use the commitment as the source of truth and verify client-side. This avoids gas costs per login and latency issues.

### Challenges to Solve
- **Secret storage:** Can't store raw secret on-chain (public). Must use commitment hash `H(secret)`
- **Time synchronization:** Block timestamps have ~12s variance. Tolerance window needs to be wider than standard TOTP
- **Gas costs:** Even on Solana (~$0.00025), per-login gas adds up. Session-based approach recommended
- **Speed:** Block confirmation takes time. Verify client-side using on-chain commitment, not wait for block confirmation

### Why It's Not Just Fancy Shit
- The legal/compliance crowd cares about **trust architecture**
- "We use Google OAuth" doesn't inspire confidence for document sealing
- Maps directly to their threat model: insider threats, regulatory compulsion, data breaches
- Passkeys as primary, wallet as optional — best of both worlds

### Auth Flow Decision
- **Primary:** Passkeys (WebAuthn) — backed by Apple, Google, Microsoft. Biometric IS the key. No password, no server-side session. Private key never leaves device.
- **Optional:** Wallet connect for blockchain anchoring flow
- **The story:** *"We can't identify you. We don't want to. Your passkey proves you're you without telling us who you are."*

---

## 4. Design System

### Color Palette
```css
--cream: #F7F5F0;      /* Main background */
--cream-2: #F4F1EA;    /* Section alternates */
--cream-3: #EDE9E0;    /* Borders, subtle fills */
--ink: #0B0B0B;        /* Primary text */
--ink-soft: #1c1c1a;   /* Secondary text */
--teal: #3C878B;       /* Primary accent */
--teal-deep: #2F6C70;  /* Dark teal for hover/active */
--teal-light: #e8f4f4; /* Light teal for badges/highlights */
--green: #3FE672;      /* Chart line */
--muted: #8A8884;      /* Tertiary text */
--muted-2: #6b6864;    /* Quaternary text */
--border: #E6E2D9;     /* Primary borders */
--border-2: #dcd7cb;   /* Secondary borders */
--red: #e85d5d;        /* Destructive actions (Shred only) */
--purple: #8b7cf6;     /* Secondary accent (Seals this month) */
```

**Design rule:** Teal is the primary accent for everything. Only Shred/destroy actions use red. No multicolor chaos — stat changes are teal, audit log badges are teal, compliance scores are teal. Purple is used sparingly for "Seals this month" bars.

### Typography
- **Headings:** Plus Jakarta Sans (weight 700-800)
- **Body:** Inter (weight 400-600)
- **Monospace:** JetBrains Mono (for hashes)

### Liquid Glass Navbar
Apple iOS 26 Liquid Glass aesthetic — floating pill nav with:
- **Glass base:** `blur(40px) saturate(180%) brightness(1.08)` with semi-transparent background
- **Specular highlight:** Gradient that follows mouse position and shifts on scroll
- **Chromatic edge:** Rainbow-tinted border that rotates with mouse (light splitting at glass edges)
- **Noise grain:** SVG `feTurbulence` overlay at 3% opacity — frosted glass texture
- **Refraction:** SVG `feDisplacementMap` filter for subtle content distortion behind glass
- **Depth on shrink:** When scrolled past 80px, blur increases to 60px, saturation to 200%
- **Inset light:** Double `inset` box-shadow — top highlight + bottom reflection like curved glass

### Scroll Reveal (iOS Blur)
- Every section starts blurred (12px) + slightly scaled down + shifted
- Sections smoothly unblur into view with `cubic-bezier` ease
- **Bidirectional:** Sections re-blur when scrolling back up (not just one-way reveal)
- Uses `IntersectionObserver` — no scroll jank, GPU-accelerated via `will-change`

### Hero Entrance Animation
Choreographed staggered entrance on page load:
| Element | Animation | Delay |
|---|---|---|
| Page | Fade in from black | 0.1s |
| Nav pill | Slide down + fade | 0s |
| Hero h1 | Fade up | 0.15s |
| Hero paragraph | Fade up | 0.35s |
| Hero art | Slide in from right | 0.25s |
| Photo card 1 | Slide in from left | 0.5s |
| Photo card 2 | Slide in from right | 0.6s |
| Float cards | Slide in from sides | 0.7s–0.75s |
| Chip card | Scale up | 0.8s |
| Typewriter | Starts after 0.4s | — |
| Buttons | Fade up after typing | — |

All using `cubic-bezier(0.16, 1, 0.3, 1)` — Apple's spring easing.

### Typewriter Hero
- "Documents sealed." types out first character by character
- "Compliance proven." follows on second line with teal color
- Blinking cursor while typing, clean finish
- Curved SVG swoosh underline appears under "Compliance proven." after typing completes
- Underline uses `clip-path` animation for left-to-right reveal

---

## 5. Pages Built

### Landing Page (`index.html`)
- Full responsive design
- Hero with typewriter animation
- Liquid Glass floating pill navbar (shrinks on scroll)
- "How It Works" section with Seal / Verify / Shred tabs
- "Why Anchr" feature grid with embedded dashboard mockup
- "The Audit Trail" marquee with document cards
- Testimonial carousel (3 mock compliance officer quotes)
- Trusted organizations grid (Deloitte, KPMG, EY, PwC + top law firms)
- CTA section
- Footer with columns: Vault, Compliance, Resources, Company

### Vault Page (`vault.html`)
- Supabase-style 48px icon-only sidebar
- Top header with breadcrumb, search (⌘K), avatar
- Stats row: Documents Sealed, Anchored on-chain, Active Keys, Crypto-Shredded
- Drag-and-drop upload zone with hover/drag states
- 5-step encryption overlay: Read file → AES-256 encrypt → SHA-256 hash → Compute Merkle root → Anchor on-chain
- Merkle root result display (64-char hex hash in JetBrains Mono)
- File table: Document, Hash, Status badge, Date, Shred action button
- Crypto-shred confirmation dialog + visual state change
- SVG icons throughout (no emojis)

### Dashboard (`dashboard.html`)
- Same sidebar + header layout
- Stats row: Documents Sealed, Merkle Roots Anchored, Verification Checks, Crypto-Shreds
- Toolbar: Filter, Sort, "Seal Document" primary button
- Two-column grid:
  - **Left:** Audit log table (Action badge, Document, Hash, Actor, Time)
  - **Right:** Compliance score ring (animated SVG), Chain of custody timeline, Vault usage bars
- All audit badges unified to teal (Seal, Anchor, Verify = teal; Shred = red)
- Chain of custody is the ONLY section with icons (lock, anchor, checkmark, user)
- Stat change text all teal (+12.3% this week, etc.)

---

## 6. Technical Stack

### Frontend
- Pure HTML/CSS/JS — no framework, no build step
- Google Fonts: Plus Jakarta Sans, Inter, JetBrains Mono
- SVG icons (inline, no icon library)
- SVG filters for Liquid Glass effect

### Deployment
- **Platform:** Render (free tier)
- **Docker:** nginx:alpine serving static files
- **nginx.conf:** Listens on port 10000 (Render's default)
- **Dockerfile copies:** `COPY *.html /usr/share/nginx/html/` + `COPY nginx.conf`

### Encryption (Planned)
- Web Crypto API for client-side AES-256 encryption
- SHA-256 hashing for Merkle root generation
- No server-side processing of plaintext ever

### Blockchain (Planned)
- Smart contract for Merkle root anchoring
- Commit-reveal pattern for blockchain TOTP
- Chain: TBD (Solana for speed/cost, or Ethereum for ecosystem)

---

## 7. Design Decisions Log

| Decision | Rationale |
|---|---|
| Name "Anchr" | Vowel-drop gives YC/startup aesthetic. One syllable, 5 letters, works as verb |
| Teal as primary | Legal/compliance vibe. More trustworthy than blue, more distinctive |
| Cream background | Premium feel, not clinical white. Warmer for legal audience |
| No emojis anywhere | Professional, hackathon-appropriate. SVG icons only |
| Icons only on chain of custody | Timeline narrates sequence — icons help tell the story. Everywhere else is clean |
| Unified teal badges | No multicolor jam. Only Shred gets red (destructive action) |
| Liquid Glass nav | Inspired by iOS 26. Signals "modern security product" not "regular SaaS" |
| Passkeys over social auth | Aligns with zero-knowledge narrative. Social auth contradicts the positioning |
| Blockquote TOTP | Trust math, not companies. Maps to legal threat model |
| Stat changes all teal | No green/red noise. Teal = progress, consistent throughout |
| Purple only on seals bar | Secondary accent, used sparingly |

---

## 8. Git History (Clean)

```
07d99fb Clean up dashboard — remove stat icons, unify all badges to teal, fix score colors
db6b3ab Remove all emojis — replace with SVG icons, teal stat changes, unified audit badges
7e43437 Redesign dashboard and vault — Supabase-style icon sidebar, clean card layout, cream/teal palette
a384958 Smooth landing entry — staggered entrance animations for all hero elements
93207e0 Restore curved underline — SVG swoosh that auto-sizes to text width
a84bd32 Fix underline — CSS pseudo-element that auto-sizes to text width
7628844 Fix underline position, speed up typewriter, fix Dockerfile to serve all pages
4ce7031 Add vault UI with encryption flow and compliance dashboard with audit log + chain of custody
471af95 Fix typewriter — smooth character-by-character with blinking cursor
8660701 Fix nav CTA overflow — shrink buttons, shorten labels
108e150 Implement Liquid Glass navbar with refraction, specular highlights, and chromatic edges
cca4687 Add floating pill navbar + bidirectional blur reveal
979ea52 Fix nginx config for Render deployment
75600cb Add Dockerfile for Render deployment
6f700c1 Initial commit: Anchr landing page with typewriter + scroll reveal
```

**Note:** No co-author footers on commits. Clean history.

---

## 9. What's Next

### Priority 1 — Hackathon Win
1. **Real encryption** — Implement Web Crypto API so files actually encrypt client-side
2. **Blockchain TOTP auth flow** — Smart contract + passkey UI on the vault
3. **Smart contract** — Merkle root anchoring on testnet

### Priority 2 — Product Polish
4. **Pricing section** — 3-tier cards (Free / Pro / Enterprise)
5. **Security badges section** — SOC 2, GDPR, HIPAA icons + zero-knowledge copy
6. **Mobile polish** — Test on phone sizes, fix overflow

### Priority 3 — Nice to Have
7. **Favicon + OG image** — Anchr logo for social sharing
8. **Loading state / skeleton screens** — Feels more production-ready
9. **404 page** — Branded "Document not found" page
10. **Demo video** — 60-second screen recording of full flow

---

## 10. Key Quotes from Session

> *"Our auth flow is starting to sound stronger than the build itself"*

> *"What if we created an authenticator but blockchain version? On sign in you go to the authenticator crypto version, a smart contract is triggered, you copy the code from your device and paste in the site. Smart contract on blockchain not a DB verifies it."*

> *"It's not just fancy — it's genuinely more secure for your use case. The legal/compliance crowd will eat this up because it maps directly to their threat model: insider threats, regulatory compulsion, data breaches."*

> *"I repeat, no Codebuff affiliations"*

---

## 11. Files

```
anchr/
├── index.html        (46KB — Landing page with Liquid Glass nav, typewriter, blur reveal)
├── vault.html        (24KB — Vault UI with encryption flow, file table, shred)
├── dashboard.html    (27KB — Compliance dashboard with audit log, score ring, timeline)
├── Dockerfile        (186B — nginx:alpine static serving)
├── nginx.conf        (168B — Port 10000 config)
└── HANDOFF.md        (This file)
```

---

*Generated from a build session. No external affiliations.*
