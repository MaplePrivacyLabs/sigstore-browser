/*
 * Managed-key bundle verification.
 *
 * Verifies bundles signed with a long-lived key the caller already trusts
 * (for example a cloud KMS key used through `cosign attest-blob --key`),
 * instead of a Fulcio certificate. The caller's key is the only key used:
 * the bundle's publicKey.hint is never used to find or install one, and there
 * is no certificate, issuer or workflow fallback.
 *
 * Transparency log, checkpoint, timestamp and body checks reuse the modules of
 * the certificate flow. By default the checks match that flow's posture; the
 * options below enable a stricter profile (STRICT_MANAGED_KEY_PROFILE).
 */

import {
  base64ToUint8Array,
  importKey,
  sha256,
  stringToUint8Array,
  uint8ArrayEqual,
  Uint8ArrayToHex,
  Uint8ArrayToString,
  verifySignature,
} from "@freedomofpress/crypto-browser";

import { assertBundle, DSSEEnvelope, InclusionProof, MessageSignature, SigstoreBundle, TLogEntry } from "./bundle.js";
import { preAuthEncoding } from "./dsse.js";
import { fail, type ReasonCode, VerificationError } from "./errors.js";
import { parseValidityPeriod, RawTimestampAuthority, RekorKeyInfo, TrustedRoot } from "./interfaces.js";
import { findDuplicateKey } from "./json.js";
import { ManagedPublicKey } from "./key.js";
import { BUNDLE_VERSIONS, countOperators, getBundleVersion } from "./sigstore.js";
import { verifyBundleTimestampForSignature } from "./timestamp/tsa.js";
import { verifyTLogBody } from "./tlog/body.js";
import { LogCheckpoint, SignedNote } from "./tlog/checkpoint.js";
import { verifyMerkleInclusion } from "./tlog/merkle.js";
import { verifyInclusionPromise } from "./tlog/set.js";
import { TrustedRootProvider } from "./trust/tuf.js";
import { X509Certificate } from "./x509/index.js";

const IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json";
// Same bounds as the certificate flow.
const MAX_SUBJECTS = 1024;
const MAX_SUBJECT_DIGESTS = 32;
const DEFAULT_MAX_BUNDLE_BYTES = 16 * 1024 * 1024;

export interface ManagedKeyVerifierOptions {
  /** Distinct log operators whose entries must verify (default 1). */
  tlogThreshold?: number;
  /** Distinct timestamp authority operators whose timestamps must verify (default 0). */
  tsaThreshold?: number;
  /** Bundle versions to accept (default ["0.2", "0.3"], as for certificates). */
  bundleVersions?: string[];
  /** Needed only to verify a messageSignature over a digest: verifySignatureOverDigest from "@freedomofpress/crypto-browser/noble". */
  verifyDigest?: (key: CryptoKey, digest: Uint8Array, signature: Uint8Array) => Promise<boolean>;
  /** Largest bundle accepted as JSON text or bytes, checked before parsing (default 16 MiB). */
  maxBundleBytes?: number;

  // The options below go beyond the certificate flow's checks. All default to off.

  /**
   * Accept only the canonical media type spelling, application/vnd.dev.sigstore.bundle.vX.Y+json,
   * not the legacy application/vnd.dev.sigstore.bundle+json;version=X.Y.
   */
  requireCanonicalMediaType?: boolean;

  /** Reject JSON that repeats a member name in any object. The bundle must then be passed as text or bytes. */
  rejectDuplicateKeys?: boolean;
  /** Require exactly one transparency log entry; an additional entry fails, with or without its own proof. */
  requireSingleTlogEntry?: boolean;
  /** Entry kinds to accept, as "kind/version" (for example ["hashedrekord/0.0.2"] for Rekor v2 only). */
  allowedEntryKinds?: string[];
  /** Reject entries with an integratedTime member, whatever its value. Rekor v2 sets none. */
  rejectIntegratedTime?: boolean;
  /** Reject entries with an inclusionPromise (SET) member. Rekor v2 issues none. */
  rejectInclusionPromise?: boolean;
  /** Require exactly one RFC 3161 timestamp. By default any number may be present, and all must verify. */
  requireSingleTimestamp?: boolean;
  /**
   * For Rekor v2 entries, require the checkpoint origin, and the name on the log's signature line, to
   * be the host of the entry's log's baseUrl in the trusted root. Entries naming a log outside the
   * trusted root are rejected instead of ignored. (The checkpoint must always be signed by the
   * entry's own log key.)
   */
  checkpointOriginBinding?: boolean;
}

/**
 * Strict profile for managed-key DSSE bundles: exactly the canonical v0.3 media type, unambiguous JSON, exactly one Rekor v2
 * hashedrekord entry without Rekor v1 metadata, exactly one RFC 3161 timestamp, and checkpoints bound
 * to the entry's log.
 */
export const STRICT_MANAGED_KEY_PROFILE: Readonly<ManagedKeyVerifierOptions> = Object.freeze({
  bundleVersions: ["0.3"],
  requireCanonicalMediaType: true,
  rejectDuplicateKeys: true,
  requireSingleTlogEntry: true,
  allowedEntryKinds: ["hashedrekord/0.0.2"],
  rejectIntegratedTime: true,
  rejectInclusionPromise: true,
  requireSingleTimestamp: true,
  checkpointOriginBinding: true,
});

export interface ManagedKeyDsseResult {
  payloadType: string;
  payload: Uint8Array;
  /** Times from the verified RFC 3161 timestamps. */
  timestamps: Date[];
}

/** A bundle as JSON text, UTF-8 bytes, or an already parsed object (not with rejectDuplicateKeys). */
export type BundleInput = string | Uint8Array | SigstoreBundle;

interface TrustedLog {
  logId: Uint8Array;
  baseUrl: unknown;
  // Undefined when the log's key or validity could not be loaded; only entries of this log fail.
  key?: RekorKeyInfo;
  error?: string;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const isObj = (v: unknown): v is Record<string, any> => typeof v === "object" && v !== null && !Array.isArray(v);
const present = (o: unknown, key: string): boolean => isObj(o) && o[key] !== undefined;

// Runs one verification step; an error that carries no reason code gets `code`.
async function step<T>(code: ReasonCode, fn: () => Promise<T> | T): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof VerificationError) throw e;
    fail(code, e instanceof Error ? e.message : String(e));
  }
}

function utf8Length(text: string, limit: number): number {
  // Each UTF-16 unit encodes to at most three bytes.
  return text.length > limit || text.length * 3 <= limit ? text.length : new TextEncoder().encode(text).length;
}

// The origin a Rekor v2 log signs checkpoints under: the host of its base URL, as sigstore-go derives it.
function logOrigin(baseUrl: unknown): string | undefined {
  if (typeof baseUrl !== "string") return undefined;
  try {
    const url = new URL(baseUrl);
    if ((url.protocol !== "https:" && url.protocol !== "http:") || url.username || url.password || !url.hostname) {
      return undefined;
    }
    return url.hostname.startsWith("[") ? url.hostname.slice(1, -1) : url.hostname;
  } catch {
    return undefined;
  }
}

function isRekorV2Entry(entry: TLogEntry): boolean {
  const { kind, version } = entry.kindVersion;
  return (kind === "hashedrekord" || kind === "dsse") && version === "0.0.2";
}

export class ManagedKeyVerifier {
  private readonly options: ManagedKeyVerifierOptions;
  private readonly tlogThreshold: number;
  private readonly tsaThreshold: number;
  private readonly bundleVersions: string[];
  private readonly maxBundleBytes: number;
  private logs: TrustedLog[] | undefined;
  private timestampAuthorities: RawTimestampAuthority[] = [];

  constructor(options: ManagedKeyVerifierOptions = {}) {
    this.options = { ...options };
    this.bundleVersions = [...(options.bundleVersions ?? ["0.2", "0.3"])];
    if (!this.bundleVersions.length || this.bundleVersions.some((v) => !BUNDLE_VERSIONS.includes(v))) {
      throw new Error(`bundleVersions must be a non-empty subset of ${BUNDLE_VERSIONS.join(", ")}`);
    }
    this.tlogThreshold = options.tlogThreshold ?? 1;
    this.tsaThreshold = options.tsaThreshold ?? 0;
    this.maxBundleBytes = options.maxBundleBytes ?? DEFAULT_MAX_BUNDLE_BYTES;
    for (const [name, value] of Object.entries({
      tlogThreshold: this.tlogThreshold,
      tsaThreshold: this.tsaThreshold,
      maxBundleBytes: this.maxBundleBytes,
    })) {
      if (!Number.isSafeInteger(value) || value < 0) {
        throw new Error(`${name} must be a non-negative safe integer`);
      }
    }
  }

  /**
   * Loads the transparency logs and timestamp authorities of a trusted root. Each log key and each
   * authority is loaded on its own: one that is unsupported (for example an Ed25519 key on a runtime
   * without Ed25519 and without the fallback), malformed or expired does not stop verification of
   * entries and timestamps that do not use it. Fulcio CAs and CT logs are not used.
   */
  async loadTrustedRoot(root: TrustedRoot): Promise<void> {
    if (!isObj(root)) throw new Error("Trusted root must be an object");
    const tlogs: unknown[] = Array.isArray(root.tlogs) ? root.tlogs : [];
    const logs = await Promise.all(tlogs.map(async (log): Promise<TrustedLog | undefined> => {
      let logId: Uint8Array;
      try {
        if (!isObj(log) || typeof log.logId?.keyId !== "string") return undefined;
        logId = base64ToUint8Array(log.logId.keyId);
      } catch {
        return undefined;
      }
      try {
        const { keyDetails, rawBytes } = log.publicKey ?? {};
        if (typeof keyDetails !== "string" || typeof rawBytes !== "string") throw new Error("missing public key");
        return {
          logId,
          baseUrl: log.baseUrl,
          key: {
            publicKey: await importKey(keyDetails, keyDetails, rawBytes),
            logId,
            hashAlgorithm: typeof log.hashAlgorithm === "string" ? log.hashAlgorithm : "",
            operator: typeof log.operator === "string" ? log.operator : "",
            validFor: parseValidityPeriod(log.publicKey.validFor),
          },
        };
      } catch (e) {
        return { logId, baseUrl: log.baseUrl, error: e instanceof Error ? e.message : String(e) };
      }
    }));
    const authorities: unknown[] = Array.isArray(root.timestampAuthorities) ? root.timestampAuthorities : [];
    this.timestampAuthorities = authorities.filter((ca): ca is RawTimestampAuthority => {
      try {
        if (!isObj(ca)) return false;
        parseValidityPeriod(ca.validFor);
        const certs = ca.certChain?.certificates;
        if (!Array.isArray(certs) || certs.length === 0) return false;
        certs.forEach((c) => X509Certificate.parse(base64ToUint8Array(c.rawBytes)));
        return true;
      } catch {
        return false;
      }
    });
    this.logs = logs.filter((l): l is TrustedLog => l !== undefined);
  }

  /** Loads the trusted root through TUF (Sigstore's production repository by default). */
  async loadTrustedRootWithTUF(tufProvider?: TrustedRootProvider): Promise<void> {
    const provider = tufProvider || new TrustedRootProvider();
    await this.loadTrustedRoot(await provider.getTrustedRoot());
  }

  /**
   * Verifies a DSSE bundle signed with `publicKey` and returns its payload. The caller checks the
   * payload (for example the in-toto statement's subject and predicate). Throws a VerificationError
   * whose `code` is one of REASON_CODES.
   *
   * @param publicKey PEM "PUBLIC KEY" or DER SubjectPublicKeyInfo of an ECDSA P-256 or P-384 key.
   */
  async verifyDsse(bundle: BundleInput, publicKey: string | Uint8Array): Promise<ManagedKeyDsseResult> {
    const key = ManagedPublicKey.from(publicKey);
    let env: DSSEEnvelope | undefined;
    const { timestamps } = await this.verifyBundle(bundle, key, "dsse", async (parsed) => {
      env = parsed.dsseEnvelope;
      if (!env) fail("content-unsupported", "Bundle does not contain a DSSE envelope");
      await this.verifyDsseSignature(env, key);
    });
    if (!env) fail("content-unsupported", "Bundle does not contain a DSSE envelope");
    return {
      payloadType: env.payloadType,
      payload: base64ToUint8Array(env.payload),
      timestamps,
    };
  }

  /**
   * Verifies a bundle signed with `publicKey` over `data`: a messageSignature over the artifact, or a
   * DSSE in-toto statement with a subject whose SHA-256 is the artifact's. With `isDigestOnly`, `data`
   * is the artifact's 32-byte SHA-256 digest.
   */
  async verifyArtifact(
    bundle: BundleInput,
    publicKey: string | Uint8Array,
    data: Uint8Array,
    isDigestOnly = false,
  ): Promise<true> {
    const key = ManagedPublicKey.from(publicKey);
    if (isDigestOnly && data.byteLength !== 32) {
      throw new Error("SHA-256 digest must be exactly 32 bytes");
    }
    await this.verifyBundle(bundle, key, "artifact", async (parsed) => {
      if (parsed.dsseEnvelope) {
        await this.verifyDsseSignature(parsed.dsseEnvelope, key);
        await this.verifySubject(parsed.dsseEnvelope, data, isDigestOnly);
      } else {
        await this.verifyMessageSignature(parsed.messageSignature, key, data, isDigestOnly);
      }
    });
    return true;
  }

  private async verifyDsseSignature(env: DSSEEnvelope, key: ManagedPublicKey): Promise<void> {
    const verified = await step("dsse-signature-invalid", async () =>
      verifySignature(
        await key.publicKey,
        preAuthEncoding(env.payloadType, base64ToUint8Array(env.payload)),
        base64ToUint8Array(env.signatures[0].sig),
        key.hash,
      ),
    );
    if (!verified) fail("dsse-signature-invalid", "DSSE signature verification failed");
  }

  private async verifySubject(env: DSSEEnvelope, data: Uint8Array, isDigestOnly: boolean): Promise<void> {
    if (env.payloadType !== IN_TOTO_PAYLOAD_TYPE) {
      fail("payload-type-unsupported", `Unsupported DSSE payload type: ${env.payloadType}`);
    }
    const statement = await step("artifact-mismatch", () => JSON.parse(Uint8ArrayToString(base64ToUint8Array(env.payload))));
    const subjects: unknown = statement?.subject;
    if (!Array.isArray(subjects) || subjects.length === 0 || subjects.length > MAX_SUBJECTS) {
      fail("artifact-mismatch", `DSSE payload must have between 1 and ${MAX_SUBJECTS} subjects`);
    }
    const artifactDigest = Uint8ArrayToHex(isDigestOnly ? data : await sha256(data));
    let matched = false;
    for (const subject of subjects) {
      const digests = isObj(subject) ? subject.digest : undefined;
      if (!isObj(digests) || Object.keys(digests).length > MAX_SUBJECT_DIGESTS) {
        fail("artifact-mismatch", `Invalid DSSE subject digest map (maximum ${MAX_SUBJECT_DIGESTS} digests)`);
      }
      matched ||= typeof digests.sha256 === "string" && artifactDigest === digests.sha256.toLowerCase();
    }
    if (!matched) fail("artifact-mismatch", `Artifact digest ${artifactDigest} does not match any subject in DSSE payload`);
  }

  private async verifyMessageSignature(
    { messageDigest, signature }: MessageSignature,
    key: ManagedPublicKey,
    data: Uint8Array,
    isDigestOnly: boolean,
  ): Promise<void> {
    const digest = isDigestOnly ? data : await sha256(data);
    if (messageDigest.algorithm !== "SHA2_256" || !uint8ArrayEqual(digest, base64ToUint8Array(messageDigest.digest))) {
      fail("artifact-mismatch", "Artifact digest does not match the bundle message digest");
    }
    const sig = base64ToUint8Array(signature);
    const cryptoKey = await key.publicKey;
    let verified: boolean;
    if (isDigestOnly) {
      if (!this.options.verifyDigest) throw new Error("Digest-only verification needs the verifyDigest option");
      const verifyDigest = this.options.verifyDigest;
      verified = await step("message-signature-invalid", () => verifyDigest(cryptoKey, data, sig));
    } else {
      verified = await step("message-signature-invalid", () => verifySignature(cryptoKey, data, sig, key.hash));
    }
    if (!verified) fail("message-signature-invalid", "Artifact signature verification failed");
  }

  // Parses and checks the bundle in the order of the strict profile, so that the first failure (and
  // its reason code) does not depend on the implementation: structure and profile rules, then the
  // signature (`verifyContent`), the log entries and the timestamps.
  private async verifyBundle(
    input: BundleInput,
    key: ManagedPublicKey,
    content: "dsse" | "artifact",
    verifyContent: (bundle: SigstoreBundle) => Promise<void>,
  ): Promise<{ bundle: SigstoreBundle; timestamps: Date[] }> {
    const logs = this.logs;
    if (!logs) throw new Error("Trusted root is not loaded");
    const opts = this.options;

    // Input bound and JSON.
    let parsed: unknown;
    if (typeof input === "string" || input instanceof Uint8Array) {
      const size = typeof input === "string" ? utf8Length(input, this.maxBundleBytes) : input.byteLength;
      if (size > this.maxBundleBytes) fail("bundle-too-large", `Bundle is larger than ${this.maxBundleBytes} bytes`);
      const text = typeof input === "string"
        ? input
        : await step("bundle-malformed", () => new TextDecoder("utf-8", { fatal: true }).decode(input));
      if (opts.rejectDuplicateKeys) {
        const duplicate = await step("bundle-malformed", () => findDuplicateKey(text));
        if (duplicate !== undefined) fail("duplicate-json-key", `Bundle JSON repeats the member ${duplicate}`);
      }
      parsed = await step("bundle-malformed", () => JSON.parse(text));
    } else {
      if (opts.rejectDuplicateKeys) {
        throw new TypeError("rejectDuplicateKeys needs the bundle as JSON text or bytes");
      }
      parsed = input;
    }
    if (!isObj(parsed)) fail("bundle-malformed", "Bundle is not a JSON object");
    const vm = parsed.verificationMaterial;

    // One variant per oneof: content, and verification material.
    if (
      ["messageSignature", "dsseEnvelope"].filter((k) => present(parsed, k)).length > 1 ||
      ["publicKey", "certificate", "x509CertificateChain"].filter((k) => present(vm, k)).length > 1
    ) {
      fail("conflicting-oneof", "Bundle has more than one variant of its content or verification material");
    }
    let version: string;
    try {
      version = getBundleVersion(typeof parsed.mediaType === "string" ? parsed.mediaType : "", this.bundleVersions);
    } catch {
      fail("media-type-unsupported", `Unsupported bundle media type: ${String(parsed.mediaType)}`);
    }
    if (opts.requireCanonicalMediaType && parsed.mediaType !== `application/vnd.dev.sigstore.bundle.v${version}+json`) {
      fail("media-type-unsupported", `Bundle media type must be spelled application/vnd.dev.sigstore.bundle.v${version}+json`);
    }
    if (!isObj(vm) || !isObj(vm.publicKey)) {
      fail("verification-material-unsupported", "Managed-key verification needs a bundle with publicKey verification material");
    }
    const env = parsed.dsseEnvelope;
    const dsse = isObj(env) && Array.isArray(env.signatures) && env.signatures.length === 1;
    if (!(dsse || (content === "artifact" && isObj(parsed.messageSignature)))) {
      fail("content-unsupported", content === "dsse"
        ? "Bundle must contain a DSSE envelope with exactly one signature"
        : "Bundle must contain a messageSignature or a DSSE envelope with exactly one signature");
    }

    // Transparency log entry and timestamp counts, kinds and Rekor v1 metadata.
    const entries: unknown[] = Array.isArray(vm.tlogEntries) ? vm.tlogEntries : [];
    if (opts.requireSingleTlogEntry && entries.length !== 1) {
      fail("tlog-entry-count", `Exactly one transparency log entry is required, found ${entries.length}`);
    }
    for (const entry of entries) {
      const kv = isObj(entry) ? entry.kindVersion : undefined;
      if (opts.allowedEntryKinds && !opts.allowedEntryKinds.includes(`${kv?.kind}/${kv?.version}`)) {
        fail("tlog-entry-kind", `Transparency log entry kind ${kv?.kind}/${kv?.version} is not accepted`);
      }
      if (opts.rejectIntegratedTime && present(entry, "integratedTime")) {
        fail("integrated-time-present", "Transparency log entry must not carry an integratedTime");
      }
      if (opts.rejectInclusionPromise && present(entry, "inclusionPromise")) {
        fail("inclusion-promise-present", "Transparency log entry must not carry an inclusion promise");
      }
    }
    if (opts.requireSingleTimestamp) {
      const timestamps = isObj(vm.timestampVerificationData) ? vm.timestampVerificationData.rfc3161Timestamps : undefined;
      if (!Array.isArray(timestamps) || timestamps.length !== 1) {
        fail("timestamp-count", "Exactly one RFC 3161 timestamp is required");
      }
    }

    // Full structural validation, as for certificate bundles.
    await step("bundle-malformed", () => assertBundle(parsed, "publicKey"));
    const bundle = parsed as SigstoreBundle;

    await verifyContent(bundle);
    const integratedTimes = await this.verifyTlogEntries(bundle, key, logs, version !== "0.1");

    const signature = base64ToUint8Array(
      bundle.dsseEnvelope ? bundle.dsseEnvelope.signatures[0].sig : bundle.messageSignature.signature,
    );
    const verified = await verifyBundleTimestampForSignature(
      bundle.verificationMaterial.timestampVerificationData,
      signature,
      this.timestampAuthorities,
    );
    const tsaOperators = countOperators(new Set(verified.map((t) => t.operator)));
    if (tsaOperators < this.tsaThreshold) {
      fail("timestamp-threshold", `Not enough verified TSA operators: ${tsaOperators} < ${this.tsaThreshold}`);
    }
    if (integratedTimes.length + verified.length === 0) {
      fail("timestamp-count", "No verified observer timestamp anchors the signature in time.");
    }
    return { bundle, timestamps: verified.map((t) => t.signingTime) };
  }

  // Verifies every entry from a trusted log and returns the integrated times bound by verified SETs.
  private async verifyTlogEntries(
    bundle: SigstoreBundle,
    key: ManagedPublicKey,
    logs: TrustedLog[],
    requireProof: boolean,
  ): Promise<Date[]> {
    const operators = new Set<string>();
    const integratedTimes: Date[] = [];
    for (const entry of bundle.verificationMaterial.tlogEntries) {
      const logId = base64ToUint8Array(entry.logId.keyId);
      const log = logs.find((l) => uint8ArrayEqual(l.logId, logId));
      if (!log) {
        if (this.options.checkpointOriginBinding) {
          fail("tlog-unknown-log", `Transparency log ${entry.logId.keyId} is not in the trusted root`);
        }
        continue;
      }
      if (!log.key) {
        fail("tlog-log-key-unsupported", `The key of transparency log ${entry.logId.keyId} could not be loaded: ${log.error}`);
      }
      const logKey = log.key;

      const promise = entry.inclusionPromise?.signedEntryTimestamp;
      if (!entry.inclusionProof && (requireProof || !promise)) {
        fail("inclusion-proof-missing", "Transparency log entry requires an inclusion proof.");
      }
      if (promise) {
        integratedTimes.push(await step("inclusion-promise-invalid", () => verifyInclusionPromise(entry, promise, logKey)));
      }
      await step("tlog-entry-malformed", () => verifyTLogBody(entry, bundle, key));
      if (entry.inclusionProof) {
        await this.verifyInclusion(entry, entry.inclusionProof, log, logKey);
      }
      operators.add(logKey.operator);
    }
    const verifiedOperators = countOperators(operators);
    if (verifiedOperators < this.tlogThreshold) {
      fail("tlog-threshold", `Not enough verified transparency logs: ${verifiedOperators} < ${this.tlogThreshold}`);
    }
    return integratedTimes;
  }

  // Inclusion proof up to the checkpoint's root, then the checkpoint: origin (if bound) and the entry's
  // log signature. Signature lines from other keys, such as witness cosignatures, are ignored.
  private async verifyInclusion(entry: TLogEntry, proof: InclusionProof, log: TrustedLog, logKey: RekorKeyInfo): Promise<void> {
    const { note, checkpoint } = await step("checkpoint-malformed", () => {
      const note = SignedNote.fromString(proof.checkpoint.envelope);
      return { note, checkpoint: LogCheckpoint.fromString(note.note) };
    });
    if (checkpoint.logSize !== BigInt(proof.treeSize) || !uint8ArrayEqual(checkpoint.logHash, base64ToUint8Array(proof.rootHash))) {
      fail("inclusion-proof-invalid", "Checkpoint does not match inclusion proof");
    }
    await step("inclusion-proof-invalid", () => verifyMerkleInclusion(entry));

    let origin: string | undefined;
    if (this.options.checkpointOriginBinding && isRekorV2Entry(entry)) {
      origin = logOrigin(log.baseUrl);
      if (origin === undefined || checkpoint.origin !== origin) {
        fail("checkpoint-origin-mismatch", `Checkpoint origin ${JSON.stringify(checkpoint.origin)} does not match the entry's log ${JSON.stringify(origin ?? log.baseUrl)}`);
      }
    }
    const data = stringToUint8Array(note.note);
    for (const sig of note.signatures) {
      if (!uint8ArrayEqual(sig.keyHint, logKey.logId.subarray(0, 4)) || (origin !== undefined && sig.name !== origin)) {
        continue;
      }
      if (await verifySignature(logKey.publicKey, data, sig.signature, logKey.hashAlgorithm).catch(() => false)) {
        return;
      }
    }
    fail("checkpoint-signature-invalid", `Checkpoint has no valid signature from the entry's log ${entry.logId.keyId}`);
  }
}
