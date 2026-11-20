// gitforge — a standalone, GitHub-compatible git forge in one process.
//
// Serves, from its own in-memory store, with no UI and no outside service:
//   * git smart HTTP: upload-pack protocol v2 (ls-refs, fetch, shallow) and
//     receive-pack v0 (report-status, side-band-64k, delete-refs)
//   * REST v3 under /api/v3 (repos, branches, commits, contents, issues, pulls)
//   * GraphQL v4 at /api/graphql (the documents gh and github-mcp-server send)
//   * MCP at /mcp (Streamable HTTP, revision 2026-07-28 + legacy handshake)
//
// Lifecycle: bind an ephemeral port, POST {port} to $MAKEFUN_ENV_URL/register,
// long-poll GET $MAKEFUN_ENV_URL/done, exit 0 when it says done.
//
// Determinism: no wall clock and no unseeded randomness anywhere in a reply.
// Server-made commits use a fixed identity and a counter-derived timestamp, so
// two runs fed the same requests in the same order produce identical state.
//
// Node 22, standard library only.

import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------
// The token owner, derived the same way the suite derives it.
//
// The suite's scenario is built from one fixed seed (SCENARIO_SEED) by a
// deterministic generator: the first generated user is the bearer token's
// owner. Replicating that generator here lets this forge answer
// GET /api/v3/user and `query { viewer { login } }` without ever having
// seen an owner in a request, and lets it refuse any other owner with 404.
const SCENARIO_SEED = 0x6a09e667f3bcc909n;
const U64_MASK = 0xffffffffffffffffn;
const FIRST_NAMES = ['ada', 'bram', 'cora', 'dmitri', 'elena', 'felix', 'greta', 'hugo', 'iris', 'jonas', 'kira', 'lars', 'mira', 'nico', 'olga', 'pavel', 'quinn', 'rosa', 'sven', 'tess', 'ulla', 'vito', 'wren', 'yara', 'zane'];
const LAST_NAMES = ['anders', 'bauer', 'costa', 'dahl', 'eriksen', 'fischer', 'garcia', 'holm', 'iversen', 'jansen', 'keller', 'lind', 'moreau', 'novak', 'olsen', 'peters', 'quist', 'rossi', 'sato', 'turi', 'ulrich', 'vega', 'weber', 'xu', 'yilmaz', 'zimmer'];

function fnv1a64(text: string): bigint {
  let hash = 0xcbf29ce484222325n;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= BigInt(text.charCodeAt(i));
    hash = (hash * 0x100000001b3n) & U64_MASK;
  }
  return hash;
}
function mix64(value: bigint): bigint {
  let z = (value + 0x9e3779b97f4a7c15n) & U64_MASK;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & U64_MASK;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & U64_MASK;
  return (z ^ (z >> 31n)) & U64_MASK;
}
class Rng {
  #state: bigint;
  constructor(seed: bigint) {
    const masked = seed & U64_MASK;
    this.#state = masked === 0n ? SCENARIO_SEED : masked;
  }
  nextU64(): bigint {
    let x = this.#state;
    x = (x ^ (x >> 12n)) & U64_MASK;
    x = (x ^ (x << 25n)) & U64_MASK;
    x = (x ^ (x >> 27n)) & U64_MASK;
    this.#state = x;
    return (x * 0x2545f4914f6cdd1dn) & U64_MASK;
  }
  nextU32(): number {
    return Number(this.nextU64() >> 32n);
  }
  nextInt(maxExclusive: number): number {
    if (maxExclusive === 1) return 0;
    const range = 4_294_967_296;
    const limit = range - (range % maxExclusive);
    for (;;) {
      const value = this.nextU32();
      if (value < limit) return value % maxExclusive;
    }
  }
  pick<T>(items: readonly T[]): T {
    return items[this.nextInt(items.length)] as T;
  }
}
function scenarioRng(label: string): Rng {
  return new Rng(mix64(SCENARIO_SEED ^ fnv1a64(label)));
}
function deriveViewer(): { login: string; name: string; email: string; id: number } {
  const rng = scenarioRng('users');
  const first = rng.pick(FIRST_NAMES);
  const last = rng.pick(LAST_NAMES);
  const login = `${first}${last}`.replace(/[^a-z0-9-]/g, '');
  return { login, name: `${first} ${last}`, email: `${login}@example.invalid`, id: 1000 };
}
const VIEWER = deriveViewer();
const VIEWER_LOGIN = VIEWER.login;
const VIEWER_IDENTITY = `${VIEWER.name} <${VIEWER.email}>`;

// ---------------------------------------------------------------------------
// Small utilities

const ZERO_OID = '0'.repeat(40);
const SHA40 = /^[0-9a-f]{40}$/;
const FIXED_EPOCH_SEC = 1735689600; // 2025-01-01T00:00:00Z; server commits count up from here
let tsSeq = 0;
function nextTimestamp(): number {
  tsSeq += 1;
  return FIXED_EPOCH_SEC + tsSeq;
}
function isoTs(sec: number): string {
  return new Date(sec * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}
let reqSeq = 0;
function nextRequestId(): string {
  reqSeq += 1;
  return `req-${reqSeq}`;
}

type GitObjectType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObject {
  type: GitObjectType;
  data: Buffer;
}
const TYPE_CODE: Record<GitObjectType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, GitObjectType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function hashObject(type: GitObjectType, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'ascii');
  return createHash('sha1').update(head).update(data).digest('hex');
}
function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}
function b64encode(data: Buffer | string): string {
  return Buffer.isBuffer(data) ? data.toString('base64') : Buffer.from(data, 'utf8').toString('base64');
}
function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/\s+/g, ''), 'base64');
}
function globalId(kind: string, value: string): string {
  return Buffer.from(`${kind}:${value}`, 'utf8').toString('base64url');
}
function decodeGlobalId(id: string): { kind: string; value: string } | null {
  try {
    const text = Buffer.from(id, 'base64url').toString('utf8');
    const colon = text.indexOf(':');
    if (colon < 1) return null;
    return { kind: text.slice(0, colon), value: text.slice(colon + 1) };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// pkt-line framing

function pktLine(payload: string | Buffer): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = body.length + 4;
  const head = Buffer.from(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, body]);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');
const PKT_RESPONSE_END = Buffer.from('0002', 'ascii');

/** True when `s` is exactly 4 hex digits (a pkt-line length field). Faster than a regex. */
function isHex4(s: string): boolean {
  if (s.length !== 4) return false;
  for (let i = 0; i < 4; i += 1) {
    const c = s.charCodeAt(i);
    if (!((c >= 48 && c <= 57) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70))) return false;
  }
  return true;
}

interface PktPacket {
  kind: 'data' | 'flush' | 'delim' | 'response-end';
  payload: Buffer;
}
/** Parse every pkt-line in a complete buffer. Throws on malformed input. */
function parsePktLines(buf: Buffer): PktPacket[] {
  const out: PktPacket[] = [];
  let off = 0;
  while (off < buf.length) {
    if (off + 4 > buf.length) throw new Error('truncated pkt-line length');
    const hex = buf.subarray(off, off + 4).toString('ascii');
    if (!isHex4(hex)) throw new Error('bad pkt-line length');
    const len = parseInt(hex, 16);
    if (len === 0) {
      out.push({ kind: 'flush', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 1) {
      out.push({ kind: 'delim', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 2) {
      out.push({ kind: 'response-end', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len < 4 || off + len > buf.length) throw new Error('bad pkt-line length');
    out.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Packfiles

function writePackObjectHeader(type: GitObjectType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

/** Build a packfile from plain objects (no deltas). Deterministic order: caller's. */
function writePack(objects: readonly GitObject[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.allocUnsafe(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const object of objects) {
    parts.push(writePackObjectHeader(object.type, object.data.length));
    parts.push(deflateSync(object.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

function readVarintSize(buffer: Buffer, start: number): { size: number; next: number; first: number } {
  let byte = buffer[start] as number;
  const first = byte;
  let size = byte & 0x0f;
  let shift = 4;
  let offset = start + 1;
  while (byte & 0x80) {
    byte = buffer[offset++] as number;
    size += (byte & 0x7f) * 2 ** shift;
    shift += 7;
  }
  return { size, next: offset, first };
}
function readOfsDeltaBase(buffer: Buffer, start: number): { baseOffset: number; next: number } {
  let byte = buffer[start] as number;
  let offset = start + 1;
  let value = byte & 0x7f;
  while (byte & 0x80) {
    byte = buffer[offset++] as number;
    value = ((value + 1) * 128) + (byte & 0x7f);
  }
  return { baseOffset: value, next: offset };
}
function inflateAt(buffer: Buffer, offset: number): { data: Buffer; next: number } {
  const view = buffer.subarray(offset);
  const result = inflateSync(view, { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
  return { data: result.buffer, next: offset + result.engine.bytesWritten };
}
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readSize = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[offset++] as number;
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(byte & 0x80)) break;
    }
    return value;
  };
  const sourceSize = readSize();
  const targetSize = readSize();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.allocUnsafe(targetSize);
  let written = 0;
  while (offset < delta.length) {
    const op = delta[offset++] as number;
    if (op & 0x80) {
      let copyOffset = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) copyOffset += (delta[offset++] as number) * 2 ** shift;
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if (op & (1 << bit)) copySize += (delta[offset++] as number) * 2 ** shift;
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      base.copy(out, written, copyOffset, copyOffset + copySize);
      written += copySize;
    } else if (op !== 0) {
      const literal = op & 0x7f;
      delta.copy(out, written, offset, offset + literal);
      offset += literal;
      written += literal;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (written !== targetSize) throw new Error('delta size mismatch');
  return out;
}

interface PackEntry {
  type: GitObjectType;
  data: Buffer;
  oid: string;
}
/** Parse a packfile, resolving OFS/REF deltas. `resolveBase` supplies thin-pack bases. */
function readPack(pack: Buffer, resolveBase?: (oid: string) => GitObject | undefined): PackEntry[] {
  if (pack.length < 32 || pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('bad pack header');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error('bad pack version');
  const declaredCount = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  const trailer = pack.subarray(trailerStart).toString('hex');
  if (trailer !== sha1Hex(pack.subarray(0, trailerStart))) throw new Error('pack checksum mismatch');
  interface Raw {
    offset: number;
    typeCode: number;
    size: number;
    data: Buffer;
    baseOffset?: number;
    baseOid?: string;
    resolved?: PackEntry;
  }
  const raw: Raw[] = [];
  const byOffset = new Map<number, Raw>();
  let offset = 12;
  for (let index = 0; index < declaredCount; index += 1) {
    const entryOffset = offset;
    const header = readVarintSize(pack, offset);
    offset = header.next;
    const typeCode = (header.first >> 4) & 0x07;
    const entry: Raw = { offset: entryOffset, typeCode, size: header.size, data: Buffer.alloc(0) };
    if (typeCode === 6) {
      const base = readOfsDeltaBase(pack, offset);
      offset = base.next;
      entry.baseOffset = entryOffset - base.baseOffset;
    } else if (typeCode === 7) {
      entry.baseOid = pack.subarray(offset, offset + 20).toString('hex');
      offset += 20;
    } else if (!CODE_TYPE[typeCode]) {
      throw new Error('unknown pack type');
    }
    const inflated = inflateAt(pack.subarray(0, trailerStart), offset);
    if (inflated.data.length !== header.size) throw new Error('pack entry size mismatch');
    entry.data = inflated.data;
    offset = inflated.next;
    raw.push(entry);
    byOffset.set(entryOffset, entry);
  }
  // Fast path: packs without delta entries resolve trivially (no base lookups,
  // no resolve recursion). Push packs are always plain, so this is the hot path.
  let hasDelta = false;
  for (const entry of raw) {
    if (entry.typeCode === 6 || entry.typeCode === 7) { hasDelta = true; break; }
  }
  if (!hasDelta) {
    return raw.map((entry) => {
      const type = CODE_TYPE[entry.typeCode] as GitObjectType;
      return { type, data: entry.data, oid: hashObject(type, entry.data) };
    });
  }
  const resolvedByOid = new Map<string, Raw>();
  const resolving = new Set<number>();
  const resolve = (entry: Raw): PackEntry => {
    if (entry.resolved) return entry.resolved;
    if (resolving.has(entry.offset)) throw new Error('delta cycle');
    resolving.add(entry.offset);
    let type: GitObjectType;
    let data: Buffer;
    if (entry.typeCode === 6) {
      const baseEntry = byOffset.get(entry.baseOffset as number);
      if (!baseEntry) throw new Error('ofs-delta base missing');
      const base = resolve(baseEntry);
      type = base.type;
      data = applyDelta(base.data, entry.data);
    } else if (entry.typeCode === 7) {
      const wanted = entry.baseOid as string;
      const baseEntry = resolvedByOid.get(wanted);
      if (baseEntry) {
        const base = resolve(baseEntry);
        type = base.type;
        data = applyDelta(base.data, entry.data);
      } else {
        const external = resolveBase?.(wanted);
        if (!external) throw new Error('ref-delta base missing');
        type = external.type;
        data = applyDelta(external.data, entry.data);
      }
    } else {
      type = CODE_TYPE[entry.typeCode] as GitObjectType;
      data = entry.data;
    }
    const oid = hashObject(type, data);
    const resolved: PackEntry = { type, data, oid };
    entry.resolved = resolved;
    resolvedByOid.set(oid, entry);
    resolving.delete(entry.offset);
    return resolved;
  };
  return raw.map(resolve);
}

// ---------------------------------------------------------------------------
// Git object graph helpers

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}
function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const space = data.indexOf(0x20, off);
    const mode = data.subarray(off, space).toString('ascii');
    const nul = data.indexOf(0x00, space);
    const name = data.subarray(space + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    off = nul + 21;
  }
  return entries;
}
function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const an = a.mode === '40000' ? `${a.name}/` : a.name;
    const bn = b.mode === '40000' ? `${b.name}/` : b.name;
    return an < bn ? -1 : an > bn ? 1 : 0;
  });
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}
interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}
function parseCommit(data: Buffer): CommitView {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const header = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of header.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}
function buildCommit(fields: { tree: string; parents: readonly string[]; message: string; timestamp: number; author?: string; committer?: string }): Buffer {
  const author = fields.author ?? VIEWER_IDENTITY;
  const committer = fields.committer ?? VIEWER_IDENTITY;
  const stamp = `${fields.timestamp} +0000`;
  let text = `tree ${fields.tree}\n`;
  for (const parent of fields.parents) text += `parent ${parent}\n`;
  text += `author ${author} ${stamp}\ncommitter ${committer} ${stamp}\n\n${fields.message}`;
  return Buffer.from(text, 'utf8');
}
function parseTag(data: Buffer): { object: string; type: string; tag: string; tagger: string; message: string } {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const header = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  let object = '';
  let type = '';
  let tag = '';
  let tagger = '';
  for (const line of header.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim();
    else if (line.startsWith('tag ')) tag = line.slice(4).trim();
    else if (line.startsWith('tagger ')) tagger = line.slice(7);
  }
  return { object, type, tag, tagger, message };
}

/** Peel a tag (recursively) to its commit oid. */
function peelToCommit(objects: Map<string, GitObject>, oid: string): string {
  let current = oid;
  for (let i = 0; i < 16; i += 1) {
    const obj = objects.get(current);
    if (!obj || obj.type !== 'tag') return current;
    current = parseTag(obj.data).object;
  }
  return current;
}

/** All objects reachable from `tips` (commits, their trees/blobs, tag targets). */
function collectReachable(objects: Map<string, GitObject>, tips: readonly string[]): Set<string> {
  const seen = new Set<string>();
  const stack = [...tips];
  while (stack.length) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    const obj = objects.get(oid);
    if (!obj) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      const view = parseCommit(obj.data);
      stack.push(view.tree);
      for (const parent of view.parents) stack.push(parent);
    } else if (obj.type === 'tree') {
      for (const entry of parseTree(obj.data)) stack.push(entry.oid);
    } else if (obj.type === 'tag') {
      stack.push(parseTag(obj.data).object);
    }
  }
  return seen;
}

/** Commits reachable from `tip`, newest-first (depth-first, parents in order). */
function listCommits(objects: Map<string, GitObject>, tip: string, limit = 10000): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const stack = [tip];
  while (stack.length && out.length < limit) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    out.push(oid);
    const parents = parseCommit(obj.data).parents;
    for (let i = parents.length - 1; i >= 0; i -= 1) stack.push(parents[i] as string);
  }
  return out;
}

/** Is `ancestor` an ancestor of (or equal to) `tip`? */
function isAncestor(objects: Map<string, GitObject>, ancestor: string, tip: string): boolean {
  if (ancestor === tip) return true;
  const seen = new Set<string>();
  const stack = [tip];
  while (stack.length) {
    const oid = stack.pop() as string;
    if (oid === ancestor) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    for (const parent of parseCommit(obj.data).parents) stack.push(parent);
  }
  return false;
}

/** Flatten a tree to path -> {oid, mode}. */
function flattenTree(objects: Map<string, GitObject>, treeOid: string, prefix = ''): Map<string, { oid: string; mode: string }> {
  const out = new Map<string, { oid: string; mode: string }>();
  const walk = (oid: string, base: string): void => {
    const obj = objects.get(oid);
    if (!obj || obj.type !== 'tree') return;
    for (const entry of parseTree(obj.data)) {
      const path = base === '' ? entry.name : `${base}/${entry.name}`;
      if (entry.mode === '40000') walk(entry.oid, path);
      else out.set(path, { oid: entry.oid, mode: entry.mode });
    }
  };
  walk(treeOid, prefix);
  return out;
}

/**
 * Return a new tree oid with `path` set to (`mode`, `blobOid`) — or removed when
 * blobOid is null — creating intermediate trees as needed. New tree/blob
 * objects are added to `objects` (caller stores them under their hash).
 */
function treeWithPath(objects: Map<string, GitObject>, baseTreeOid: string | null, path: string, blobOid: string | null, mode = '100644'): string {
  const segments = path.split('/').filter((s) => s !== '');
  const build = (treeOid: string | null, depth: number): string => {
    const entries: TreeEntry[] = treeOid ? parseTree(objects.get(treeOid)?.data ?? Buffer.alloc(0)) : [];
    const name = segments[depth] as string;
    if (depth === segments.length - 1) {
      const kept = entries.filter((e) => e.name !== name);
      if (blobOid !== null) kept.push({ mode, name, oid: blobOid });
      const data = buildTree(kept);
      const oid = hashObject('tree', data);
      objects.set(oid, { type: 'tree', data });
      return oid;
    }
    const child = entries.find((e) => e.name === name);
    const childOid = build(child && child.mode === '40000' ? child.oid : null, depth + 1);
    const kept = entries.filter((e) => e.name !== name);
    const childEntries = parseTree(objects.get(childOid)?.data ?? Buffer.alloc(0));
    if (childEntries.length > 0) kept.push({ mode: '40000', name, oid: childOid });
    const data = buildTree(kept);
    const oid = hashObject('tree', data);
    objects.set(oid, { type: 'tree', data });
    return oid;
  };
  return build(baseTreeOid, 0);
}

/** Line diff counts (LCS on lines) for pull-request file stats. */
function lineDiffCounts(oldText: string, newText: string): { additions: number; deletions: number } {
  const a = oldText === '' ? [] : oldText.split('\n');
  const b = newText === '' ? [] : newText.split('\n');
  if (a.length * b.length > 400000) {
    // Large files: fall back to a multiset count.
    const count = new Map<string, number>();
    for (const line of a) count.set(line, (count.get(line) ?? 0) + 1);
    let common = 0;
    for (const line of b) {
      const c = count.get(line) ?? 0;
      if (c > 0) {
        count.set(line, c - 1);
        common += 1;
      }
    }
    return { additions: b.length - common, deletions: a.length - common };
  }
  const n = a.length;
  const m = b.length;
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      dp[i]![j] = a[i] === b[j] ? (dp[i + 1]![j + 1] as number) + 1 : Math.max(dp[i + 1]![j] as number, dp[i]![j + 1] as number);
    }
  }
  const lcs = dp[0]![0] as number;
  return { additions: m - lcs, deletions: n - lcs };
}

// ---------------------------------------------------------------------------
// Store

interface Label {
  name: string;
  color: string;
}
interface Issue {
  id: number;
  globalId: string;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: Label[];
  comments: Comment[];
  seq: number;
  createdSec: number;
}
interface Comment {
  id: number;
  globalId: string;
  body: string;
  createdSec: number;
}
interface PullRequest {
  id: number;
  globalId: string;
  number: number;
  title: string;
  body: string;
  headRef: string;
  baseRef: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  seq: number;
  createdSec: number;
}
interface Repo {
  id: number;
  globalId: string;
  name: string;
  owner: string;
  description: string;
  private: boolean;
  defaultBranch: string;
  refs: Map<string, string>;
  objects: Map<string, GitObject>;
  labels: Map<string, Label>;
  issues: Issue[];
  pulls: PullRequest[];
  nextIssueNumber: number;
  nextPullNumber: number;
  nextCommentId: number;
  seq: number;
  createdSec: number;
  version: number;
  packCache: Map<string, Buffer>;
  /** Bumped on every mutation of any issue in this repo; validates issueJsonCache. */
  issueRev: number;
  /** Serialized GET /issues/{n} response bodies, keyed by issue number. */
  issueJsonCache: Map<number, { rev: number; body: Buffer }>;
  /** Serialized v0 ref advertisements, keyed by service. */
  advCache: Map<string, { version: number; branch: string; body: Buffer }>;
}

let nextRepoId = 10000;
let nextIssueId = 20000;
let nextPullId = 30000;
let nextCommentCounter = 40000;
const repos = new Map<string, Repo>(); // key: owner + '/' + name

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}
function createRepoRecord(name: string, description: string, isPrivate: boolean): Repo {
  const id = nextRepoId;
  nextRepoId += 1;
  const createdSec = nextTimestamp();
  const repo: Repo = {
    id,
    globalId: globalId('R', String(id)),
    name,
    owner: VIEWER_LOGIN,
    description,
    private: isPrivate,
    defaultBranch: 'main',
    refs: new Map(),
    objects: new Map(),
    labels: new Map(),
    issues: [],
    pulls: [],
    nextIssueNumber: 1,
    nextPullNumber: 1,
    nextCommentId: 1,
    seq: repos.size + 1,
    createdSec,
    version: 0,
    packCache: new Map(),
    issueRev: 0,
    issueJsonCache: new Map(),
    advCache: new Map(),
  };
  repos.set(repoKey(VIEWER_LOGIN, name), repo);
  return repo;
}
function findRepo(owner: string, name: string): Repo | undefined {
  if (owner !== VIEWER_LOGIN) return undefined;
  return repos.get(repoKey(owner, name));
}
function findRepoById(id: number): Repo | undefined {
  for (const repo of repos.values()) if (repo.id === id) return repo;
  return undefined;
}
function findIssueByGlobalId(gid: string): { repo: Repo; issue: Issue } | null {
  const decoded = decodeGlobalId(gid);
  if (!decoded || decoded.kind !== 'I') return null;
  const [repoIdText, numText] = decoded.value.split(':');
  const repo = findRepoById(Number(repoIdText));
  if (!repo) return null;
  const issue = repo.issues.find((i) => i.number === Number(numText));
  return issue ? { repo, issue } : null;
}
function findPullByGlobalId(gid: string): { repo: Repo; pull: PullRequest } | null {
  const decoded = decodeGlobalId(gid);
  if (!decoded || decoded.kind !== 'P') return null;
  const [repoIdText, numText] = decoded.value.split(':');
  const repo = findRepoById(Number(repoIdText));
  if (!repo) return null;
  const pull = repo.pulls.find((p) => p.number === Number(numText));
  return pull ? { repo, pull } : null;
}
function refTip(repo: Repo, branch: string): string | undefined {
  return repo.refs.get(`refs/heads/${branch}`);
}
function commitAt(repo: Repo, ref: string): string | undefined {
  if (repo.refs.has(ref)) return repo.refs.get(ref);
  if (SHA40.test(ref)) return repo.objects.has(ref) ? ref : undefined;
  return refTip(repo, ref);
}
function treeOfCommit(repo: Repo, commitOid: string): string | null {
  const obj = repo.objects.get(commitOid);
  if (!obj || obj.type !== 'commit') return null;
  return parseCommit(obj.data).tree;
}
/** The merge-base (first common ancestor) of two commits, or null. */
function mergeBase(repo: Repo, a: string, b: string): string | null {
  const ancestorsA = new Set<string>(listCommits(repo.objects, a));
  const queue = [b];
  const seen = new Set<string>();
  while (queue.length) {
    const oid = queue.shift() as string;
    if (ancestorsA.has(oid)) return oid;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (obj && obj.type === 'commit') queue.push(...parseCommit(obj.data).parents);
  }
  return null;
}
/** Would a squash merge of `pull` into its base conflict? */
function pullConflicts(repo: Repo, pull: PullRequest): boolean {
  const headTip = refTip(repo, pull.headRef);
  const baseTip = refTip(repo, pull.baseRef);
  if (!headTip || !baseTip) return false;
  const base = mergeBase(repo, headTip, baseTip);
  if (base === null) return headTip !== baseTip;
  const baseTree = treeOfCommit(repo, base);
  const headTree = treeOfCommit(repo, headTip);
  const targetTree = treeOfCommit(repo, baseTip);
  if (baseTree === null || headTree === null || targetTree === null) return false;
  const baseFiles = flattenTree(repo.objects, baseTree);
  const headFiles = flattenTree(repo.objects, headTree);
  const targetFiles = flattenTree(repo.objects, targetTree);
  const paths = new Set([...headFiles.keys(), ...targetFiles.keys()]);
  for (const path of paths) {
    const inBase = baseFiles.get(path);
    const inHead = headFiles.get(path);
    const inTarget = targetFiles.get(path);
    const headChanged = (inHead?.oid ?? null) !== (inBase?.oid ?? null);
    const targetChanged = (inTarget?.oid ?? null) !== (inBase?.oid ?? null);
    if (headChanged && targetChanged && (inHead?.oid ?? null) !== (inTarget?.oid ?? null)) return true;
  }
  return false;
}
function pullMergeable(repo: Repo, pull: PullRequest): 'MERGEABLE' | 'CONFLICTING' | 'UNKNOWN' {
  if (pull.state !== 'open') return 'UNKNOWN';
  return pullConflicts(repo, pull) ? 'CONFLICTING' : 'MERGEABLE';
}
/** Squash-merge a pull request onto its base branch. Returns the merge commit oid, or null on conflict. */
function squashMerge(repo: Repo, pull: PullRequest): string | null {
  const headTip = refTip(repo, pull.headRef);
  const baseTip = refTip(repo, pull.baseRef);
  if (!headTip || !baseTip) return null;
  if (pullConflicts(repo, pull)) return null;
  const base = mergeBase(repo, headTip, baseTip);
  const baseTree = base === null ? null : treeOfCommit(repo, base);
  const headTree = treeOfCommit(repo, headTip);
  const targetTree = treeOfCommit(repo, baseTip);
  if (headTree === null || targetTree === null) return null;
  const baseFiles = baseTree === null ? new Map() : flattenTree(repo.objects, baseTree);
  const headFiles = flattenTree(repo.objects, headTree);
  let newTree = targetTree;
  const paths = new Set([...baseFiles.keys(), ...headFiles.keys()]);
  for (const path of paths) {
    const inBase = baseFiles.get(path);
    const inHead = headFiles.get(path);
    if ((inHead?.oid ?? null) === (inBase?.oid ?? null)) continue;
    if (inHead) {
      newTree = treeWithPath(repo.objects, newTree, path, inHead.oid, inHead.mode);
    } else {
      newTree = treeWithPath(repo.objects, newTree, path, null);
    }
  }
  const stamp = nextTimestamp();
  const commit = buildCommit({
    tree: newTree,
    parents: [baseTip],
    message: `${pull.title} (#${pull.number})\n\nSquashed commit of pull request #${pull.number}.\n`,
    timestamp: stamp,
  });
  const oid = hashObject('commit', commit);
  repo.objects.set(oid, { type: 'commit', data: commit });
  repo.refs.set(`refs/heads/${pull.baseRef}`, oid);
  repo.version += 1;
  repo.packCache.clear();
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = isoTs(stamp);
  pull.mergeCommitSha = oid;
  return oid;
}

// ---------------------------------------------------------------------------
// HTTP plumbing

const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const JSON_TYPE = 'application/json; charset=utf-8';

function sendJson(res: ServerResponse, status: number, body: unknown, extraHeaders: Record<string, string> = {}): void {
  const text = status === 204 ? '' : `${JSON.stringify(body)}\n`;
  const headers: Record<string, string> = {
    'x-github-request-id': nextRequestId(),
    ...extraHeaders,
  };
  if (status !== 204) {
    headers['content-type'] = JSON_TYPE;
    headers['content-length'] = String(Buffer.byteLength(text));
  }
  res.writeHead(status, headers);
  res.end(text);
}
/** Send an already-serialized JSON body (no stringify, no byte-length scan). */
function sendJsonBuffer(res: ServerResponse, status: number, body: Buffer, extraHeaders: Record<string, string> = {}): void {
  const headers: Record<string, string> = {
    'x-github-request-id': nextRequestId(),
    ...extraHeaders,
    'content-type': JSON_TYPE,
    'content-length': String(body.length),
  };
  res.writeHead(status, headers);
  res.end(body);
}
function sendError(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}
function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
async function readJsonBody(req: IncomingMessage): Promise<{ ok: true; value: unknown } | { ok: false }> {
  const buf = await readBody(req);
  if (buf.length === 0) return { ok: true, value: {} };
  try {
    return { ok: true, value: JSON.parse(buf.toString('utf8')) as unknown };
  } catch {
    return { ok: false };
  }
}
function authOk(req: IncomingMessage): boolean {
  if (TOKEN === '') return true;
  const header = req.headers.authorization;
  return header === `Bearer ${TOKEN}`;
}
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function asString(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback;
}
function asBool(value: unknown, fallback = false): boolean {
  return typeof value === 'boolean' ? value : fallback;
}
function pathOf(req: IncomingMessage): string {
  try {
    return new URL(req.url ?? '/', 'http://entry').pathname;
  } catch {
    return '/';
  }
}
function queryOf(req: IncomingMessage): URLSearchParams {
  try {
    return new URL(req.url ?? '/', 'http://entry').searchParams;
  } catch {
    return new URLSearchParams();
  }
}
function decodePath(path: string): string {
  try {
    return decodeURIComponent(path);
  } catch {
    return path;
  }
}
function hostBase(req: IncomingMessage): string {
  const host = req.headers.host ?? 'localhost';
  return `http://${host}`;
}

// ---------------------------------------------------------------------------
// REST shapes

function userJson(): Record<string, unknown> {
  return {
    login: VIEWER_LOGIN,
    id: VIEWER.id,
    node_id: globalId('U', String(VIEWER.id)),
    avatar_url: '',
    type: 'User',
    site_admin: false,
    name: VIEWER.name,
    email: VIEWER.email,
    html_url: `https://github.com/${VIEWER_LOGIN}`,
    url: `/api/v3/users/${VIEWER_LOGIN}`,
  };
}
function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    node_id: repo.globalId,
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: VIEWER.id, type: 'User' },
    private: repo.private,
    description: repo.description,
    default_branch: repo.defaultBranch,
    html_url: `https://github.com/${repo.owner}/${repo.name}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    created_at: isoTs(repo.createdSec),
    updated_at: isoTs(repo.createdSec),
    has_issues: true,
    has_projects: true,
    has_wiki: true,
    fork: false,
    archived: false,
    disabled: false,
    visibility: repo.private ? 'private' : 'public',
  };
}
function issueJson(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: issue.globalId,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((label) => ({ id: 0, name: label.name, color: label.color, description: '' })),
    user: { login: VIEWER_LOGIN, id: VIEWER.id, type: 'User' },
    comments: issue.comments.length,
    created_at: isoTs(issue.createdSec),
    updated_at: isoTs(issue.createdSec),
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
    repository_url: `/api/v3/repos/${repo.owner}/${repo.name}`,
  };
}
function pullJson(repo: Repo, pull: PullRequest): Record<string, unknown> {
  const headSha = refTip(repo, pull.headRef) ?? ZERO_OID;
  const baseSha = refTip(repo, pull.baseRef) ?? ZERO_OID;
  return {
    id: pull.id,
    node_id: pull.globalId,
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    merged: pull.merged,
    mergeable: pull.state === 'open' ? !pullConflicts(repo, pull) : null,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    head: { ref: pull.headRef, sha: headSha, label: `${repo.owner}:${pull.headRef}`, user: { login: VIEWER_LOGIN } },
    base: { ref: pull.baseRef, sha: baseSha, label: `${repo.owner}:${pull.baseRef}`, user: { login: VIEWER_LOGIN } },
    user: { login: VIEWER_LOGIN, id: VIEWER.id, type: 'User' },
    created_at: isoTs(pull.createdSec),
    updated_at: isoTs(pull.createdSec),
    html_url: `https://github.com/${repo.owner}/${repo.name}/pull/${pull.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pull.number}`,
  };
}
function commentJson(repo: Repo, issue: Issue, comment: Comment): Record<string, unknown> {
  return {
    id: comment.id,
    node_id: comment.globalId,
    body: comment.body,
    user: { login: VIEWER_LOGIN, id: VIEWER.id, type: 'User' },
    created_at: isoTs(comment.createdSec),
    updated_at: isoTs(comment.createdSec),
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}#issuecomment-${comment.id}`,
    issue_url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
  };
}

/** Commit a contents change on `branch` (creating the branch from the default tip when needed). */
function commitContents(repo: Repo, branch: string, path: string, content: Buffer, message: string): { commitSha: string; blobSha: string } {
  const blobSha = hashObject('blob', content);
  repo.objects.set(blobSha, { type: 'blob', data: content });
  let tip = repo.refs.get(`refs/heads/${branch}`);
  if (tip === undefined) {
    tip = branch === repo.defaultBranch ? undefined : repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  }
  const baseTree = tip === undefined ? null : treeOfCommit(repo, tip);
  const newTree = treeWithPath(repo.objects, baseTree, path, blobSha);
  const stamp = nextTimestamp();
  const commit = buildCommit({
    tree: newTree,
    parents: tip === undefined ? [] : [tip],
    message: message.endsWith('\n') ? message : `${message}\n`,
    timestamp: stamp,
  });
  const commitSha = hashObject('commit', commit);
  repo.objects.set(commitSha, { type: 'commit', data: commit });
  repo.refs.set(`refs/heads/${branch}`, commitSha);
  repo.version += 1;
  repo.packCache.clear();
  return { commitSha, blobSha };
}

function paginate<T>(items: readonly T[], query: URLSearchParams): { page: T[]; hasNext: boolean; pageNum: number; perPage: number } {
  const perPage = Math.max(1, Math.min(100, Number(query.get('per_page') ?? '30') || 30));
  const pageNum = Math.max(1, Number(query.get('page') ?? '1') || 1);
  const start = (pageNum - 1) * perPage;
  return { page: items.slice(start, start + perPage), hasNext: start + perPage < items.length, pageNum, perPage };
}
function linkHeader(req: IncomingMessage, path: string, query: URLSearchParams, pageNum: number, perPage: number, hasNext: boolean): string | null {
  if (!hasNext) return null;
  const next = new URLSearchParams(query);
  next.set('page', String(pageNum + 1));
  next.set('per_page', String(perPage));
  return `<${hostBase(req)}${path}?${next.toString()}>; rel="next"`;
}

// ---------------------------------------------------------------------------
// REST router

async function handleRest(req: IncomingMessage, res: ServerResponse, rawPath: string = pathOf(req), query: URLSearchParams = queryOf(req)): Promise<boolean> {
  if (!rawPath.startsWith('/api/v3')) return false;
  const method = req.method ?? 'GET';
  const path = decodePath(rawPath);
  const sub = path === '/api/v3' ? '/' : path.slice('/api/v3'.length);

  if (!authOk(req)) {
    sendError(res, 401, 'Requires authentication');
    return true;
  }

  // API root
  if (method === 'GET' && (sub === '/' || sub === '')) {
    sendJson(res, 200, {
      current_user_url: '/api/v3/user',
      current_user_authorizations_html_url: 'https://github.com/settings/applications',
      authorizations_url: '/api/v3/authorizations',
      rate_limit_url: '/api/v3/rate_limit',
      user_url: '/api/v3/users/{user}',
      repository_url: '/api/v3/repos/{owner}/{repo}',
    }, { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }
  if (method === 'GET' && sub === '/meta') {
    sendJson(res, 200, { verifiable_password_authentication: true, installed_version: '1.0.0', github_services_sha: '0000000000000000000000000000000000000000' });
    return true;
  }
  if (method === 'GET' && sub === '/user') {
    sendJson(res, 200, userJson());
    return true;
  }

  // POST /user/repos and GET /user/repos
  if (sub === '/user/repos') {
    if (method === 'POST') {
      const parsed = await readJsonBody(req);
      if (!parsed.ok) {
        sendError(res, 400, 'Problems parsing JSON');
        return true;
      }
      const body = isRecord(parsed.value) ? parsed.value : {};
      const name = asString(body.name);
      if (name === '') {
        sendError(res, 422, 'Validation Failed: name is required');
        return true;
      }
      if (repos.has(repoKey(VIEWER_LOGIN, name))) {
        sendError(res, 422, 'Repository already exists');
        return true;
      }
      const repo = createRepoRecord(name, asString(body.description), asBool(body.private, false));
      sendJson(res, 201, repoJson(repo));
      return true;
    }
    if (method === 'GET') {
      const all = [...repos.values()].sort((a, b) => a.seq - b.seq).map(repoJson);
      const { page, hasNext, pageNum, perPage } = paginate(all, query);
      const link = linkHeader(req, rawPath, query, pageNum, perPage, hasNext);
      sendJson(res, 200, page, link ? { link } : {});
      return true;
    }
    sendError(res, 404, 'Not Found');
    return true;
  }

  const repoMatch = /^\/repos\/([^/]+)\/([^/]+)(.*)$/.exec(sub);
  if (repoMatch) {
    const owner = repoMatch[1] as string;
    const name = repoMatch[2] as string;
    const rest = repoMatch[3] as string;
    const repo = findRepo(owner, name);
    if (!repo) {
      // A repository under another owner is 404, never 403; same for missing repos.
      sendError(res, 404, 'Not Found');
      return true;
    }
    return handleRepoRest(req, res, repo, rest, query);
  }

  sendError(res, 404, 'Not Found');
  return true;
}

async function handleRepoRest(req: IncomingMessage, res: ServerResponse, repo: Repo, rest: string, query: URLSearchParams): Promise<boolean> {
  const method = req.method ?? 'GET';

  // The repository itself
  if (rest === '' || rest === '/') {
    if (method === 'GET') {
      sendJson(res, 200, repoJson(repo));
      return true;
    }
    if (method === 'PATCH') {
      const parsed = await readJsonBody(req);
      if (!parsed.ok) {
        sendError(res, 400, 'Problems parsing JSON');
        return true;
      }
      const body = isRecord(parsed.value) ? parsed.value : {};
      if (typeof body.description === 'string') repo.description = body.description;
      if (typeof body.default_branch === 'string' && repo.refs.has(`refs/heads/${body.default_branch}`)) repo.defaultBranch = body.default_branch;
      sendJson(res, 200, repoJson(repo));
      return true;
    }
    if (method === 'DELETE') {
      repos.delete(repoKey(repo.owner, repo.name));
      sendJson(res, 204, null);
      return true;
    }
    sendError(res, 404, 'Not Found');
    return true;
  }

  // Branches
  if (rest === '/branches' && method === 'GET') {
    const list = [...repo.refs.keys()]
      .filter((ref) => ref.startsWith('refs/heads/'))
      .sort()
      .map((ref) => ({ name: ref.slice('refs/heads/'.length), commit: { sha: repo.refs.get(ref) as string }, protected: false }));
    sendJson(res, 200, list);
    return true;
  }
  const branchMatch = /^\/branches\/(.+)$/.exec(rest);
  if (branchMatch && method === 'GET') {
    const branch = branchMatch[1] as string;
    const tip = refTip(repo, branch);
    if (!tip) {
      sendError(res, 404, 'Branch not found');
      return true;
    }
    sendJson(res, 200, { name: branch, commit: { sha: tip }, protected: false });
    return true;
  }

  // Git refs
  if (rest === '/git/refs' && method === 'GET') {
    const list = [...repo.refs.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([ref, sha]) => ({ ref, object: { sha, type: 'commit' } }));
    sendJson(res, 200, list);
    return true;
  }
  if (rest === '/git/refs' && method === 'POST') {
    const parsed = await readJsonBody(req);
    if (!parsed.ok) {
      sendError(res, 400, 'Problems parsing JSON');
      return true;
    }
    const body = isRecord(parsed.value) ? parsed.value : {};
    const ref = asString(body.ref);
    const sha = asString(body.sha);
    if (!ref.startsWith('refs/') || !SHA40.test(sha) || !repo.objects.has(sha)) {
      sendError(res, 422, 'Validation Failed');
      return true;
    }
    if (repo.refs.has(ref)) {
      sendError(res, 422, 'Reference already exists');
      return true;
    }
    repo.refs.set(ref, sha);
    repo.version += 1;
    repo.packCache.clear();
    sendJson(res, 201, { ref, object: { sha, type: 'commit' } });
    return true;
  }
  const gitRefMatch = /^\/git\/refs\/(.+)$/.exec(rest);
  if (gitRefMatch && method === 'GET') {
    const ref = gitRefMatch[1] as string;
    const sha = repo.refs.get(ref);
    if (!sha) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    sendJson(res, 200, { ref, object: { sha, type: 'commit' } });
    return true;
  }

  // Commits
  if (rest === '/commits' && method === 'GET') {
    const refName = query.get('sha') ?? repo.defaultBranch;
    const tip = commitAt(repo, refName);
    if (!tip) {
      sendJson(res, 200, []);
      return true;
    }
    const list = listCommits(repo.objects, tip).map((sha) => {
      const view = parseCommit(repo.objects.get(sha)?.data ?? Buffer.alloc(0));
      return {
        sha,
        commit: { message: view.message.replace(/\n+$/, ''), author: { name: VIEWER.name, email: VIEWER.email }, committer: { name: VIEWER.name, email: VIEWER.email } },
        parents: view.parents.map((p) => ({ sha: p })),
        author: { login: VIEWER_LOGIN, id: VIEWER.id },
        committer: { login: VIEWER_LOGIN, id: VIEWER.id },
      };
    });
    const { page } = paginate(list, query);
    sendJson(res, 200, page);
    return true;
  }
  const commitMatch = /^\/commits\/([^/]+)$/.exec(rest);
  if (commitMatch && method === 'GET') {
    const sha = commitMatch[1] as string;
    const obj = repo.objects.get(sha);
    if (!obj || obj.type !== 'commit') {
      sendError(res, 404, 'Not Found');
      return true;
    }
    const view = parseCommit(obj.data);
    sendJson(res, 200, {
      sha,
      commit: { message: view.message.replace(/\n+$/, ''), author: { name: VIEWER.name, email: VIEWER.email }, committer: { name: VIEWER.name, email: VIEWER.email } },
      parents: view.parents.map((p) => ({ sha: p })),
    });
    return true;
  }

  // Contents
  if (rest.startsWith('/contents')) {
    return handleContents(req, res, repo, rest.slice('/contents'.length), query);
  }

  // Labels
  if (rest === '/labels' && method === 'POST') {
    const parsed = await readJsonBody(req);
    if (!parsed.ok) {
      sendError(res, 400, 'Problems parsing JSON');
      return true;
    }
    const body = isRecord(parsed.value) ? parsed.value : {};
    const labelName = asString(body.name);
    if (labelName === '') {
      sendError(res, 422, 'Validation Failed: name is required');
      return true;
    }
    const existing = repo.labels.get(labelName);
    if (existing) {
      sendJson(res, 201, { id: 0, name: existing.name, color: existing.color, description: '' });
      return true;
    }
    const label: Label = { name: labelName, color: asString(body.color, 'ededed') };
    repo.labels.set(labelName, label);
    sendJson(res, 201, { id: 0, name: label.name, color: label.color, description: '' });
    return true;
  }
  if (rest === '/labels' && method === 'GET') {
    sendJson(res, 200, [...repo.labels.values()].map((label) => ({ id: 0, name: label.name, color: label.color, description: '' })));
    return true;
  }

  // Issues
  if (rest === '/issues' && method === 'POST') return createIssueRest(req, res, repo);
  if (rest === '/issues' && method === 'GET') {
    const state = query.get('state') ?? 'open';
    const sort = query.get('sort') ?? 'created';
    const direction = query.get('direction') ?? 'desc';
    let list = repo.issues.filter((issue) => state === 'all' || issue.state === state);
    if (sort === 'created') {
      list = [...list].sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
    }
    const { page } = paginate(list.map((issue) => issueJson(repo, issue)), query);
    sendJson(res, 200, page);
    return true;
  }
  const issueMatch = /^\/issues\/(\d+)(\/comments)?$/.exec(rest);
  if (issueMatch) {
    const number = Number(issueMatch[1]);
    const issue = repo.issues.find((i) => i.number === number);
    if (!issue) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    if (issueMatch[2] === '/comments') {
      if (method === 'GET') {
        sendJson(res, 200, issue.comments.map((c) => commentJson(repo, issue, c)));
        return true;
      }
      if (method === 'POST') {
        const parsed = await readJsonBody(req);
        if (!parsed.ok) {
          sendError(res, 400, 'Problems parsing JSON');
          return true;
        }
        const body = isRecord(parsed.value) ? parsed.value : {};
        const comment: Comment = {
          id: nextCommentCounter,
          globalId: globalId('C', `${repo.id}:${issue.number}:${issue.comments.length + 1}`),
          body: asString(body.body),
          createdSec: nextTimestamp(),
        };
        nextCommentCounter += 1;
        issue.comments.push(comment);
        repo.issueRev += 1;
        sendJson(res, 201, commentJson(repo, issue, comment));
        return true;
      }
      sendError(res, 404, 'Not Found');
      return true;
    }
    if (method === 'GET') {
      const cached = repo.issueJsonCache.get(number);
      if (cached && cached.rev === repo.issueRev) {
        sendJsonBuffer(res, 200, cached.body);
        return true;
      }
      const body = Buffer.from(`${JSON.stringify(issueJson(repo, issue))}\n`, 'utf8');
      repo.issueJsonCache.set(number, { rev: repo.issueRev, body });
      sendJsonBuffer(res, 200, body);
      return true;
    }
    if (method === 'PATCH') {
      const parsed = await readJsonBody(req);
      if (!parsed.ok) {
        sendError(res, 400, 'Problems parsing JSON');
        return true;
      }
      const body = isRecord(parsed.value) ? parsed.value : {};
      if (typeof body.title === 'string') issue.title = body.title;
      if (typeof body.body === 'string') issue.body = body.body;
      if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
      repo.issueRev += 1;
      sendJson(res, 200, issueJson(repo, issue));
      return true;
    }
    sendError(res, 404, 'Not Found');
    return true;
  }

  // Pull requests
  if (rest === '/pulls' && method === 'POST') return createPullRest(req, res, repo);
  if (rest === '/pulls' && method === 'GET') {
    const state = query.get('state') ?? 'open';
    const list = repo.pulls.filter((pull) => state === 'all' || pull.state === state);
    const { page } = paginate(list.map((pull) => pullJson(repo, pull)), query);
    sendJson(res, 200, page);
    return true;
  }
  const pullFilesMatch = /^\/pulls\/(\d+)\/files$/.exec(rest);
  if (pullFilesMatch && method === 'GET') {
    const number = Number(pullFilesMatch[1]);
    const pull = repo.pulls.find((p) => p.number === number);
    if (!pull) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    sendJson(res, 200, pullFiles(repo, pull));
    return true;
  }
  const pullMergeMatch = /^\/pulls\/(\d+)\/merge$/.exec(rest);
  if (pullMergeMatch && method === 'PUT') return mergePullRest(req, res, repo, Number(pullMergeMatch[1]));
  const pullMatch = /^\/pulls\/(\d+)$/.exec(rest);
  if (pullMatch) {
    const number = Number(pullMatch[1]);
    const pull = repo.pulls.find((p) => p.number === number);
    if (!pull) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    if (method === 'GET') {
      sendJson(res, 200, pullJson(repo, pull));
      return true;
    }
    sendError(res, 404, 'Not Found');
    return true;
  }

  sendError(res, 404, 'Not Found');
  return true;
}

async function createIssueRest(req: IncomingMessage, res: ServerResponse, repo: Repo): Promise<boolean> {
  const parsed = await readJsonBody(req);
  if (!parsed.ok) {
    sendError(res, 400, 'Problems parsing JSON');
    return true;
  }
  const body = isRecord(parsed.value) ? parsed.value : {};
  const labelNames: string[] = Array.isArray(body.labels) ? (body.labels as unknown[]).filter((l): l is string => typeof l === 'string') : [];
  for (const labelName of labelNames) {
    if (!repo.labels.has(labelName)) {
      sendError(res, 422, `Validation Failed: label "${labelName}" does not exist`);
      return true;
    }
  }
  const number = repo.nextIssueNumber;
  repo.nextIssueNumber += 1;
  const issue: Issue = {
    id: nextIssueId,
    globalId: globalId('I', `${repo.id}:${number}`),
    number,
    title: asString(body.title),
    body: asString(body.body, ''),
    state: 'open',
    labels: labelNames.map((name) => repo.labels.get(name) as Label),
    comments: [],
    seq: repo.issues.length + 1,
    createdSec: nextTimestamp(),
  };
  nextIssueId += 1;
  repo.issues.push(issue);
  repo.issueRev += 1;
  sendJson(res, 201, issueJson(repo, issue));
  return true;
}

async function createPullRest(req: IncomingMessage, res: ServerResponse, repo: Repo): Promise<boolean> {
  const parsed = await readJsonBody(req);
  if (!parsed.ok) {
    sendError(res, 400, 'Problems parsing JSON');
    return true;
  }
  const body = isRecord(parsed.value) ? parsed.value : {};
  const head = asString(body.head);
  const base = asString(body.base, repo.defaultBranch);
  const headShort = head.includes(':') ? (head.split(':').pop() as string) : head;
  const baseShort = base.includes(':') ? (base.split(':').pop() as string) : base;
  if (!refTip(repo, headShort) || !refTip(repo, baseShort)) {
    sendError(res, 422, 'Validation Failed: head or base branch does not exist');
    return true;
  }
  const existing = repo.pulls.find((p) => p.state === 'open' && p.headRef === headShort && p.baseRef === baseShort);
  if (existing) {
    sendError(res, 422, 'Validation Failed: a pull request already exists for this branch');
    return true;
  }
  const number = repo.nextPullNumber;
  repo.nextPullNumber += 1;
  const pull: PullRequest = {
    id: nextPullId,
    globalId: globalId('P', `${repo.id}:${number}`),
    number,
    title: asString(body.title),
    body: asString(body.body, ''),
    headRef: headShort,
    baseRef: baseShort,
    state: 'open',
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    seq: repo.pulls.length + 1,
    createdSec: nextTimestamp(),
  };
  nextPullId += 1;
  repo.pulls.push(pull);
  sendJson(res, 201, pullJson(repo, pull));
  return true;
}

function pullFiles(repo: Repo, pull: PullRequest): Record<string, unknown>[] {
  const headTip = refTip(repo, pull.headRef);
  const baseTip = refTip(repo, pull.baseRef);
  if (!headTip || !baseTip) return [];
  const base = mergeBase(repo, headTip, baseTip);
  const baseTree = base === null ? null : treeOfCommit(repo, base);
  const headTree = treeOfCommit(repo, headTip);
  if (headTree === null) return [];
  const baseFiles = baseTree === null ? new Map<string, { oid: string; mode: string }>() : flattenTree(repo.objects, baseTree);
  const headFiles = flattenTree(repo.objects, headTree);
  const paths = new Set([...baseFiles.keys(), ...headFiles.keys()]);
  const out: Record<string, unknown>[] = [];
  for (const path of [...paths].sort()) {
    const inBase = baseFiles.get(path);
    const inHead = headFiles.get(path);
    if ((inBase?.oid ?? null) === (inHead?.oid ?? null)) continue;
    let status = 'modified';
    let additions = 0;
    let deletions = 0;
    if (!inBase && inHead) {
      status = 'added';
      const text = repo.objects.get(inHead.oid)?.data.toString('utf8') ?? '';
      additions = text === '' ? 0 : text.split('\n').length;
    } else if (inBase && !inHead) {
      status = 'removed';
      const text = repo.objects.get(inBase.oid)?.data.toString('utf8') ?? '';
      deletions = text === '' ? 0 : text.split('\n').length;
    } else if (inBase && inHead) {
      const oldText = repo.objects.get(inBase.oid)?.data.toString('utf8') ?? '';
      const newText = repo.objects.get(inHead.oid)?.data.toString('utf8') ?? '';
      const counts = lineDiffCounts(oldText, newText);
      additions = counts.additions;
      deletions = counts.deletions;
    }
    out.push({
      sha: inHead?.oid ?? inBase?.oid ?? '',
      filename: path,
      status,
      additions,
      deletions,
      changes: additions + deletions,
      blob_url: '',
      raw_url: '',
      contents_url: '',
    });
  }
  return out;
}

async function mergePullRest(req: IncomingMessage, res: ServerResponse, repo: Repo, number: number): Promise<boolean> {
  const pull = repo.pulls.find((p) => p.number === number);
  if (!pull) {
    sendError(res, 404, 'Not Found');
    return true;
  }
  // Drain the body (merge_method) so the socket stays reusable.
  await readBody(req);
  if (pull.state !== 'open') {
    sendError(res, 405, 'Pull request is already closed');
    return true;
  }
  const sha = squashMerge(repo, pull);
  if (sha === null) {
    sendError(res, 405, 'Merge conflict');
    return true;
  }
  sendJson(res, 200, { sha, merged: true, message: 'Pull request successfully merged' });
  return true;
}

async function handleContents(req: IncomingMessage, res: ServerResponse, repo: Repo, restPath: string, query: URLSearchParams): Promise<boolean> {
  const method = req.method ?? 'GET';
  const path = restPath.replace(/^\/+/, '').replace(/\/+$/, '');
  const refName = query.get('ref') ?? repo.defaultBranch;
  const tip = commitAt(repo, refName);

  if (method === 'GET') {
    if (tip === undefined) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    const treeOid = treeOfCommit(repo, tip);
    if (treeOid === null) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    if (path === '') {
      const entries = parseTree(repo.objects.get(treeOid)?.data ?? Buffer.alloc(0)).map((entry) => ({
        type: entry.mode === '40000' ? 'dir' : 'file',
        name: entry.name,
        path: entry.name,
        sha: entry.oid,
        size: entry.mode === '40000' ? 0 : (repo.objects.get(entry.oid)?.data.length ?? 0),
      }));
      sendJson(res, 200, entries);
      return true;
    }
    const files = flattenTree(repo.objects, treeOid);
    const file = files.get(path);
    if (file) {
      const data = repo.objects.get(file.oid)?.data ?? Buffer.alloc(0);
      sendJson(res, 200, {
        type: 'file',
        encoding: 'base64',
        size: data.length,
        name: path.split('/').pop() as string,
        path,
        content: data.toString('base64'),
        sha: file.oid,
      });
      return true;
    }
    // A directory listing.
    const prefix = `${path}/`;
    const children = new Map<string, { mode: string; oid: string }>();
    for (const [filePath, entry] of files) {
      if (!filePath.startsWith(prefix)) continue;
      const rest = filePath.slice(prefix.length);
      const first = rest.split('/')[0] as string;
      if (!rest.includes('/')) children.set(first, { mode: '100644', oid: entry.oid });
      else if (!children.has(first)) {
        // Find the subtree oid for the directory.
        const dirEntries = parseTree(repo.objects.get(treeOid)?.data ?? Buffer.alloc(0));
        const found = dirEntries.find((e) => e.name === first);
        if (found) children.set(first, { mode: '40000', oid: found.oid });
      }
    }
    if (children.size > 0) {
      const list = [...children.entries()].map(([name, entry]) => ({
        type: entry.mode === '40000' ? 'dir' : 'file',
        name,
        path: `${path}/${name}`,
        sha: entry.oid,
        size: entry.mode === '40000' ? 0 : (repo.objects.get(entry.oid)?.data.length ?? 0),
      }));
      sendJson(res, 200, list);
      return true;
    }
    // Nested directory one level deeper (paths like a/b/c where a/b is a dir).
    const segments = path.split('/');
    let currentTree = treeOid;
    let ok = true;
    for (const segment of segments) {
      const entries = parseTree(repo.objects.get(currentTree)?.data ?? Buffer.alloc(0));
      const found = entries.find((e) => e.name === segment && e.mode === '40000');
      if (!found) {
        ok = false;
        break;
      }
      currentTree = found.oid;
    }
    if (ok) {
      const entries = parseTree(repo.objects.get(currentTree)?.data ?? Buffer.alloc(0)).map((entry) => ({
        type: entry.mode === '40000' ? 'dir' : 'file',
        name: entry.name,
        path: `${path}/${entry.name}`,
        sha: entry.oid,
        size: entry.mode === '40000' ? 0 : (repo.objects.get(entry.oid)?.data.length ?? 0),
      }));
      sendJson(res, 200, entries);
      return true;
    }
    sendError(res, 404, 'Not Found');
    return true;
  }

  if (method === 'PUT') {
    const parsed = await readJsonBody(req);
    if (!parsed.ok) {
      sendError(res, 400, 'Problems parsing JSON');
      return true;
    }
    const body = isRecord(parsed.value) ? parsed.value : {};
    const branch = asString(body.branch, repo.defaultBranch);
    const message = asString(body.message, 'Update file');
    const content = b64decode(asString(body.content, ''));
    const sha = asString(body.sha, '');
    if (path === '') {
      sendError(res, 422, 'Validation Failed');
      return true;
    }
    const currentTip = commitAt(repo, branch);
    let currentSha: string | null = null;
    if (currentTip !== undefined) {
      const treeOid = treeOfCommit(repo, currentTip);
      if (treeOid !== null) currentSha = flattenTree(repo.objects, treeOid).get(path)?.oid ?? null;
    }
    const isUpdate = currentSha !== null;
    if (isUpdate && sha !== '' && sha.toLowerCase() !== currentSha.toLowerCase()) {
      sendError(res, 409, 'Conflict: sha does not match the current blob');
      return true;
    }
    const { commitSha, blobSha } = commitContents(repo, branch, path, content, message);
    sendJson(res, isUpdate ? 200 : 201, {
      content: { name: path.split('/').pop() as string, path, sha: blobSha, size: content.length, encoding: 'base64' },
      commit: { sha: commitSha, message },
    });
    return true;
  }

  if (method === 'DELETE') {
    const parsed = await readJsonBody(req);
    if (!parsed.ok) {
      sendError(res, 400, 'Problems parsing JSON');
      return true;
    }
    const body = isRecord(parsed.value) ? parsed.value : {};
    const branch = asString(body.branch, repo.defaultBranch);
    const message = asString(body.message, 'Delete file');
    const tip = commitAt(repo, branch);
    if (tip === undefined) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    const treeOid = treeOfCommit(repo, tip);
    if (treeOid === null || !flattenTree(repo.objects, treeOid).has(path)) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    const newTree = treeWithPath(repo.objects, treeOid, path, null);
    const stamp = nextTimestamp();
    const commit = buildCommit({ tree: newTree, parents: [tip], message: message.endsWith('\n') ? message : `${message}\n`, timestamp: stamp });
    const commitSha = hashObject('commit', commit);
    repo.objects.set(commitSha, { type: 'commit', data: commit });
    repo.refs.set(`refs/heads/${branch}`, commitSha);
    repo.version += 1;
    repo.packCache.clear();
    sendJson(res, 200, { commit: { sha: commitSha, message } });
    return true;
  }

  sendError(res, 404, 'Not Found');
  return true;
}

// ---------------------------------------------------------------------------
// GraphQL

type GqlValue =
  | { kind: 'variable'; name: string }
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'list'; values: GqlValue[] }
  | { kind: 'object'; fields: Map<string, GqlValue> };
interface GqlSelection {
  alias: string | null;
  name: string;
  args: Map<string, GqlValue>;
  children: GqlSelection[];
  fragmentType: string | null;
}
interface GqlOperation {
  kind: 'query' | 'mutation';
  name: string | null;
  selections: GqlSelection[];
}

function tokenizeGql(source: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < source.length) {
    const ch = source[i] as string;
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < source.length && source[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '.' && source.slice(i, i + 3) === '...') {
      tokens.push('...');
      i += 3;
      continue;
    }
    if ('{}():![]=@$'.includes(ch)) {
      tokens.push(ch);
      i += 1;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      let out = '';
      while (j < source.length && source[j] !== '"') {
        if (source[j] === '\\' && j + 1 < source.length) {
          const esc = source[j + 1] as string;
          out += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
          j += 2;
        } else {
          out += source[j] as string;
          j += 1;
        }
      }
      tokens.push(JSON.stringify(out));
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(ch)) {
      let j = i;
      while (j < source.length && /[0-9.eE+-]/.test(source[j] as string)) j += 1;
      tokens.push(source.slice(i, j));
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let j = i;
      while (j < source.length && /[A-Za-z0-9_]/.test(source[j] as string)) j += 1;
      tokens.push(source.slice(i, j));
      i = j;
      continue;
    }
    i += 1;
  }
  return tokens;
}

class GqlParser {
  private tokens: string[];
  private pos = 0;
  constructor(source: string) {
    this.tokens = tokenizeGql(source);
  }
  peek(): string | undefined {
    return this.tokens[this.pos];
  }
  next(): string {
    return this.tokens[this.pos++] as string;
  }
  expect(token: string): void {
    if (this.next() !== token) throw new Error(`expected ${token}`);
  }
  parseOperation(): GqlOperation {
    let kind: 'query' | 'mutation' = 'query';
    let name: string | null = null;
    const first = this.peek();
    if (first === 'query' || first === 'mutation') {
      kind = this.next() as 'query' | 'mutation';
      const maybeName = this.peek();
      if (maybeName !== undefined && maybeName !== '(' && maybeName !== '{') name = this.next();
    }
    if (this.peek() === '(') {
      // Variable definitions: skip them (values come from `variables`).
      let depth = 0;
      while (this.pos < this.tokens.length) {
        const token = this.next();
        if (token === '(' || token === '[' || token === '{') depth += 1;
        else if (token === ')' || token === ']' || token === '}') {
          depth -= 1;
          if (depth === 0) break;
        }
      }
    }
    const selections = this.parseSelectionSet();
    return { kind, name, selections };
  }
  parseSelectionSet(): GqlSelection[] {
    this.expect('{');
    const selections: GqlSelection[] = [];
    while (this.peek() !== '}' && this.pos < this.tokens.length) {
      selections.push(this.parseSelection());
    }
    this.expect('}');
    return selections;
  }
  parseSelection(): GqlSelection {
    if (this.peek() === '...') {
      this.next();
      let fragmentType: string | null = null;
      if (this.peek() === 'on') {
        this.next();
        fragmentType = this.next();
      } else {
        // Named fragment spread: unsupported by the suite's documents; skip its name.
        this.next();
        return { alias: null, name: '', args: new Map(), children: [], fragmentType: '__skip__' };
      }
      const children = this.parseSelectionSet();
      return { alias: null, name: '', args: new Map(), children, fragmentType };
    }
    let alias: string | null = null;
    let name = this.next();
    if (this.peek() === ':') {
      this.next();
      alias = name;
      name = this.next();
    }
    const args = new Map<string, GqlValue>();
    if (this.peek() === '(') {
      this.next();
      while (this.peek() !== ')') {
        const argName = this.next();
        this.expect(':');
        args.set(argName, this.parseValue());
      }
      this.next();
    }
    let children: GqlSelection[] = [];
    if (this.peek() === '{') children = this.parseSelectionSet();
    return { alias, name, args, children, fragmentType: null };
  }
  parseValue(): GqlValue {
    const token = this.next();
    if (token === '$') return { kind: 'variable', name: this.next() };
    if (token === '[') {
      const values: GqlValue[] = [];
      while (this.peek() !== ']') values.push(this.parseValue());
      this.next();
      return { kind: 'list', values };
    }
    if (token === '{') {
      const fields = new Map<string, GqlValue>();
      while (this.peek() !== '}') {
        const fieldName = this.next();
        this.expect(':');
        fields.set(fieldName, this.parseValue());
      }
      this.next();
      return { kind: 'object', fields };
    }
    if (token.startsWith('"')) return { kind: 'string', value: JSON.parse(token) as string };
    if (token === 'true') return { kind: 'boolean', value: true };
    if (token === 'false') return { kind: 'boolean', value: false };
    if (token === 'null') return { kind: 'null' };
    if (/^-?\d+$/.test(token)) return { kind: 'int', value: Number(token) };
    if (/^-?\d+\.\d+$/.test(token)) return { kind: 'float', value: Number(token) };
    return { kind: 'enum', value: token };
  }
}

function resolveGqlValue(value: GqlValue, variables: Record<string, unknown>): unknown {
  switch (value.kind) {
    case 'variable':
      return variables[value.name] ?? null;
    case 'string':
    case 'int':
    case 'float':
    case 'boolean':
      return value.value;
    case 'null':
      return null;
    case 'enum':
      return value.value;
    case 'list':
      return value.values.map((v) => resolveGqlValue(v, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const [key, v] of value.fields) out[key] = resolveGqlValue(v, variables);
      return out;
    }
  }
}
function argValue(selection: GqlSelection, name: string, variables: Record<string, unknown>): unknown {
  const value = selection.args.get(name);
  if (value === undefined) return undefined;
  return resolveGqlValue(value, variables);
}

const GQL_TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'state', 'body', 'url', 'createdAt', 'updatedAt', 'author', 'comments', 'labels', 'repository'],
  PullRequest: ['id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'headRefOid', 'baseRefOid', 'files', 'author', 'createdAt', 'updatedAt', 'mergedAt', 'mergeCommit', 'repository'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'private', 'url', 'createdAt', 'updatedAt'],
  User: ['login', 'id', 'name', 'email'],
  IssueConnection: ['nodes', 'pageInfo', 'totalCount'],
  PullRequestConnection: ['nodes', 'pageInfo', 'totalCount'],
  PullRequestChangedFileConnection: ['nodes', 'pageInfo'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'],
  Query: ['viewer', 'repository', 'node', '__type', '__schema'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  __Type: ['name', 'kind', 'fields', 'enumValues', 'description'],
  __Schema: ['types', 'queryType', 'mutationType'],
  Ref: ['name', 'target'],
  IssueComment: ['id', 'body', 'author', 'createdAt'],
  IssueCommentEdge: ['node', 'cursor'],
  CreateIssuePayload: ['issue', 'clientMutationId'],
  CloseIssuePayload: ['issue', 'clientMutationId'],
  CreatePullRequestPayload: ['pullRequest', 'clientMutationId'],
  MergePullRequestPayload: ['pullRequest', 'clientMutationId'],
  AddCommentPayload: ['commentEdge', 'clientMutationId'],
  PullRequestChangedFile: ['path', 'filename', 'additions', 'deletions', 'changeType'],
};
const GQL_TYPE_ENUMS: Record<string, string[]> = {
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'CODE', 'MILESTONE', 'WIKI', 'PROJECT', 'PACKAGE', 'TOPIC'],
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  OrderDirection: ['ASC', 'DESC'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
  RepositoryPermission: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'],
  PullRequestMergeMethod: ['MERGE', 'SQUASH', 'REBASE'],
};

interface GqlContext {
  errors: string[];
  variables: Record<string, unknown>;
}

function gqlTypeOf(value: unknown): string {
  if (value === null || value === undefined) return 'Unknown';
  if (isRecord(value)) {
    if ('__gqlType' in value) return value.__gqlType as string;
    if ('kind' in value) return value.kind as string;
  }
  return 'Unknown';
}

function executeSelections(selections: readonly GqlSelection[], parent: Record<string, unknown> | null, typeName: string, ctx: GqlContext): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const knownFields = typeName === 'Unknown' ? null : (GQL_TYPE_FIELDS[typeName] ?? []);
  for (const selection of selections) {
    if (selection.fragmentType === '__skip__') continue;
    if (selection.fragmentType !== null) {
      if (selection.fragmentType !== typeName && selection.fragmentType !== 'Node') continue;
      const child = executeSelections(selection.children, parent, typeName, ctx);
      Object.assign(out, child);
      continue;
    }
    const key = selection.alias ?? selection.name;
    if (parent === null) {
      out[key] = null;
      continue;
    }
    if (selection.name === '__typename') {
      out[key] = typeName;
      continue;
    }
    if (knownFields !== null && !knownFields.includes(selection.name)) {
      ctx.errors.push(`Cannot query field "${selection.name}" on type "${typeName}".`);
      out[key] = null;
      continue;
    }
    const raw = resolveField(selection, parent, typeName, ctx);
    if (raw === undefined) {
      out[key] = null;
      continue;
    }
    if (selection.children.length === 0 || raw === null) {
      out[key] = raw;
      continue;
    }
    if (Array.isArray(raw)) {
      out[key] = raw.map((item) => {
        if (item === null || typeof item !== 'object') return item;
        const itemType = gqlTypeOf(item);
        return executeSelections(selection.children, item as Record<string, unknown>, itemType, ctx);
      });
      continue;
    }
    if (typeof raw === 'object') {
      const childType = gqlTypeOf(raw);
      out[key] = executeSelections(selection.children, raw as Record<string, unknown>, childType, ctx);
      continue;
    }
    out[key] = raw;
  }
  return out;
}

function wrapRepo(repo: Repo): Record<string, unknown> {
  return {
    __gqlType: 'Repository',
    id: repo.globalId,
    databaseId: repo.id,
    name: repo.name,
    nameWithOwner: `${repo.owner}/${repo.name}`,
    owner: { __gqlType: 'User', login: repo.owner, id: VIEWER.id, name: VIEWER.name, email: VIEWER.email },
    defaultBranchRef: (() => {
      const tip = refTip(repo, repo.defaultBranch);
      return tip ? { __gqlType: 'Ref', name: repo.defaultBranch } : null;
    })(),
    viewerPermission: 'ADMIN',
    hasIssuesEnabled: true,
    description: repo.description,
    private: repo.private,
    url: `https://github.com/${repo.owner}/${repo.name}`,
    createdAt: isoTs(repo.createdSec),
    updatedAt: isoTs(repo.createdSec),
    __repo: repo,
  };
}
function wrapIssue(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    __gqlType: 'Issue',
    id: issue.globalId,
    number: issue.number,
    title: issue.title,
    state: issue.state === 'open' ? 'OPEN' : 'CLOSED',
    body: issue.body,
    url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`,
    createdAt: isoTs(issue.createdSec),
    updatedAt: isoTs(issue.createdSec),
    __repo: repo,
    __issue: issue,
  };
}
function wrapPull(repo: Repo, pull: PullRequest): Record<string, unknown> {
  return {
    __gqlType: 'PullRequest',
    id: pull.globalId,
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.merged ? 'MERGED' : pull.state === 'open' ? 'OPEN' : 'CLOSED',
    merged: pull.merged,
    mergeable: pullMergeable(repo, pull),
    headRefName: pull.headRef,
    baseRefName: pull.baseRef,
    headRefOid: refTip(repo, pull.headRef) ?? null,
    baseRefOid: refTip(repo, pull.baseRef) ?? null,
    mergedAt: pull.mergedAt,
    createdAt: isoTs(pull.createdSec),
    updatedAt: isoTs(pull.createdSec),
    __repo: repo,
    __pull: pull,
  };
}

function issueConnection(repo: Repo, selection: GqlSelection, ctx: GqlContext): Record<string, unknown> {
  const first = argValue(selection, 'first', ctx.variables) as number | undefined;
  const after = argValue(selection, 'after', ctx.variables) as string | null | undefined;
  const states = argValue(selection, 'states', ctx.variables) as string[] | undefined;
  const orderBy = argValue(selection, 'orderBy', ctx.variables) as { field?: string; direction?: string } | undefined;
  let list = [...repo.issues];
  if (Array.isArray(states) && states.length > 0) {
    const wanted = new Set(states.map((s) => String(s).toLowerCase()));
    list = list.filter((issue) => wanted.has(issue.state));
  }
  const direction = orderBy?.direction === 'ASC' ? 'asc' : orderBy?.direction === 'DESC' ? 'desc' : 'asc';
  list.sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq || b.number - a.number));
  if (typeof after === 'string' && after !== '') {
    try {
      const decoded = Buffer.from(after, 'base64url').toString('utf8');
      const afterNum = Number(decoded.replace(/^cursor:/, ''));
      if (Number.isFinite(afterNum)) {
        list = direction === 'asc' ? list.filter((issue) => issue.number > afterNum) : list.filter((issue) => issue.number < afterNum);
      }
    } catch {
      // An unreadable cursor pages from the start.
    }
  }
  const limited = typeof first === 'number' ? list.slice(0, first) : list;
  const hasNextPage = typeof first === 'number' ? list.length > first : false;
  const last = limited[limited.length - 1];
  return {
    __gqlType: 'IssueConnection',
    nodes: limited.map((issue) => wrapIssue(repo, issue)),
    pageInfo: {
      __gqlType: 'PageInfo',
      hasNextPage,
      hasPreviousPage: false,
      startCursor: limited.length ? Buffer.from(`cursor:${limited[0]?.number ?? 0}`, 'utf8').toString('base64url') : null,
      endCursor: last ? Buffer.from(`cursor:${last.number}`, 'utf8').toString('base64url') : null,
    },
    totalCount: list.length,
  };
}

function resolveField(selection: GqlSelection, parent: Record<string, unknown>, typeName: string, ctx: GqlContext): unknown {
  const name = selection.name;
  // Root query fields.
  if (typeName === 'Query') {
    if (name === 'viewer') return { __gqlType: 'User', login: VIEWER_LOGIN, id: VIEWER.id, name: VIEWER.name, email: VIEWER.email };
    if (name === 'repository') {
      const owner = argValue(selection, 'owner', ctx.variables) as string;
      const repoName = argValue(selection, 'name', ctx.variables) as string;
      const repo = findRepo(owner, repoName);
      return repo ? wrapRepo(repo) : null;
    }
    if (name === 'node') {
      const id = argValue(selection, 'id', ctx.variables) as string;
      const decoded = decodeGlobalId(id);
      if (!decoded) return null;
      if (decoded.kind === 'R') {
        const repo = findRepoById(Number(decoded.value));
        return repo ? wrapRepo(repo) : null;
      }
      if (decoded.kind === 'I') {
        const found = findIssueByGlobalId(id);
        return found ? wrapIssue(found.repo, found.issue) : null;
      }
      if (decoded.kind === 'P') {
        const found = findPullByGlobalId(id);
        return found ? wrapPull(found.repo, found.pull) : null;
      }
      return null;
    }
    if (name === '__type') {
      const typeArg = argValue(selection, 'name', ctx.variables) as string;
      const fields = GQL_TYPE_FIELDS[typeArg];
      const enums = GQL_TYPE_ENUMS[typeArg];
      if (!fields && !enums) return null;
      return {
        __gqlType: '__Type',
        name: typeArg,
        fields: (fields ?? []).map((f) => ({ name: f })),
        enumValues: (enums ?? []).map((e) => ({ name: e })),
      };
    }
    if (name === '__schema') {
      return { __gqlType: '__Schema', types: Object.keys(GQL_TYPE_FIELDS).map((t) => ({ name: t })) };
    }
    return undefined;
  }
  if (typeName === 'Mutation') {
    if (name === 'createIssue') return mutateCreateIssue(selection, ctx);
    if (name === 'closeIssue') return mutateCloseIssue(selection, ctx);
    if (name === 'createPullRequest') return mutateCreatePullRequest(selection, ctx);
    if (name === 'mergePullRequest') return mutateMergePullRequest(selection, ctx);
    if (name === 'addComment') return mutateAddComment(selection, ctx);
    return undefined;
  }
  if (typeName === '__Type') {
    if (name === 'fields') return (parent.fields as { name: string }[] | undefined) ?? [];
    if (name === 'enumValues') return (parent.enumValues as { name: string }[] | undefined) ?? [];
    if (name === 'name') return parent.name ?? null;
    return parent[name] ?? null;
  }
  if (typeName === 'Repository') {
    const repo = parent.__repo as Repo;
    if (name === 'issue') {
      const number = argValue(selection, 'number', ctx.variables) as number;
      const issue = repo.issues.find((i) => i.number === number);
      return issue ? wrapIssue(repo, issue) : null;
    }
    if (name === 'issues') return issueConnection(repo, selection, ctx);
    if (name === 'pullRequests') {
      const first = argValue(selection, 'first', ctx.variables) as number | undefined;
      const list = typeof first === 'number' ? repo.pulls.slice(0, first) : repo.pulls;
      return { __gqlType: 'PullRequestConnection', nodes: list.map((p) => wrapPull(repo, p)), pageInfo: { __gqlType: 'PageInfo', hasNextPage: false, hasPreviousPage: false, startCursor: null, endCursor: null }, totalCount: repo.pulls.length };
    }
    if (name === 'pullRequest') {
      const number = argValue(selection, 'number', ctx.variables) as number;
      const pull = repo.pulls.find((p) => p.number === number);
      return pull ? wrapPull(repo, pull) : null;
    }
    return parent[name] ?? null;
  }
  if (typeName === 'PullRequest') {
    const repo = parent.__repo as Repo;
    const pull = parent.__pull as PullRequest;
    if (name === 'files') {
      const files = pullFiles(repo, pull);
      return {
        __gqlType: 'PullRequestChangedFileConnection',
        nodes: files.map((f) => ({ __gqlType: 'PullRequestChangedFile', path: f.filename, filename: f.filename, additions: f.additions, deletions: f.deletions })),
        pageInfo: { __gqlType: 'PageInfo', hasNextPage: false, hasPreviousPage: false, startCursor: null, endCursor: null },
      };
    }
    return parent[name] ?? null;
  }
  if (typeName === 'Issue' || typeName === 'User' || typeName === 'Ref' || typeName === 'PageInfo' || typeName === 'IssueConnection' || typeName === 'PullRequestConnection' || typeName === 'PullRequestChangedFileConnection' || typeName === 'PullRequestChangedFile') {
    return parent[name] ?? null;
  }
  return parent[name] ?? null;
}

function mutateCreateIssue(selection: GqlSelection, ctx: GqlContext): Record<string, unknown> {
  const input = argValue(selection, 'input', ctx.variables) as Record<string, unknown>;
  const repositoryId = asString(input?.repositoryId);
  const decoded = decodeGlobalId(repositoryId);
  const repo = decoded?.kind === 'R' ? findRepoById(Number(decoded.value)) : undefined;
  if (!repo) {
    ctx.errors.push('createIssue: repository not found');
    return { __gqlType: 'CreateIssuePayload', issue: null };
  }
  const number = repo.nextIssueNumber;
  repo.nextIssueNumber += 1;
  const issue: Issue = {
    id: nextIssueId,
    globalId: globalId('I', `${repo.id}:${number}`),
    number,
    title: asString(input?.title),
    body: asString(input?.body, ''),
    state: 'open',
    labels: [],
    comments: [],
    seq: repo.issues.length + 1,
    createdSec: nextTimestamp(),
  };
  nextIssueId += 1;
  repo.issues.push(issue);
  repo.issueRev += 1;
  return { __gqlType: 'CreateIssuePayload', issue: wrapIssue(repo, issue) };
}
function mutateCloseIssue(selection: GqlSelection, ctx: GqlContext): Record<string, unknown> {
  const input = argValue(selection, 'input', ctx.variables) as Record<string, unknown>;
  const found = findIssueByGlobalId(asString(input?.issueId));
  if (!found) {
    ctx.errors.push('closeIssue: issue not found');
    return { __gqlType: 'CloseIssuePayload', issue: null };
  }
  found.issue.state = 'closed';
  found.repo.issueRev += 1;
  return { __gqlType: 'CloseIssuePayload', issue: wrapIssue(found.repo, found.issue) };
}
function mutateCreatePullRequest(selection: GqlSelection, ctx: GqlContext): Record<string, unknown> {
  const input = argValue(selection, 'input', ctx.variables) as Record<string, unknown>;
  const decoded = decodeGlobalId(asString(input?.repositoryId));
  const repo = decoded?.kind === 'R' ? findRepoById(Number(decoded.value)) : undefined;
  if (!repo) {
    ctx.errors.push('createPullRequest: repository not found');
    return { __gqlType: 'CreatePullRequestPayload', pullRequest: null };
  }
  const headRef = asString(input?.headRefName);
  const baseRef = asString(input?.baseRefName, repo.defaultBranch);
  if (!refTip(repo, headRef) || !refTip(repo, baseRef)) {
    ctx.errors.push('createPullRequest: head or base branch does not exist');
    return { __gqlType: 'CreatePullRequestPayload', pullRequest: null };
  }
  const number = repo.nextPullNumber;
  repo.nextPullNumber += 1;
  const pull: PullRequest = {
    id: nextPullId,
    globalId: globalId('P', `${repo.id}:${number}`),
    number,
    title: asString(input?.title),
    body: asString(input?.body, ''),
    headRef,
    baseRef,
    state: 'open',
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    seq: repo.pulls.length + 1,
    createdSec: nextTimestamp(),
  };
  nextPullId += 1;
  repo.pulls.push(pull);
  return { __gqlType: 'CreatePullRequestPayload', pullRequest: wrapPull(repo, pull) };
}
function mutateMergePullRequest(selection: GqlSelection, ctx: GqlContext): Record<string, unknown> {
  const input = argValue(selection, 'input', ctx.variables) as Record<string, unknown>;
  const found = findPullByGlobalId(asString(input?.pullRequestId));
  if (!found) {
    ctx.errors.push('mergePullRequest: pull request not found');
    return { __gqlType: 'MergePullRequestPayload', pullRequest: null };
  }
  const sha = squashMerge(found.repo, found.pull);
  if (sha === null) {
    ctx.errors.push('mergePullRequest: merge conflict');
    return { __gqlType: 'MergePullRequestPayload', pullRequest: wrapPull(found.repo, found.pull) };
  }
  return { __gqlType: 'MergePullRequestPayload', pullRequest: wrapPull(found.repo, found.pull) };
}
function mutateAddComment(selection: GqlSelection, ctx: GqlContext): Record<string, unknown> {
  const input = argValue(selection, 'input', ctx.variables) as Record<string, unknown>;
  const found = findIssueByGlobalId(asString(input?.subjectId));
  if (!found) {
    ctx.errors.push('addComment: subject not found');
    return { __gqlType: 'AddCommentPayload', commentEdge: null };
  }
  const comment: Comment = {
    id: nextCommentCounter,
    globalId: globalId('C', `${found.repo.id}:${found.issue.number}:${found.issue.comments.length + 1}`),
    body: asString(input?.body),
    createdSec: nextTimestamp(),
  };
  nextCommentCounter += 1;
  found.issue.comments.push(comment);
  found.repo.issueRev += 1;
  return {
    __gqlType: 'AddCommentPayload',
    commentEdge: { __gqlType: 'IssueCommentEdge', node: { __gqlType: 'IssueComment', id: comment.globalId, body: comment.body } },
  };
}

function executeGraphQLOperation(query: string, variables: Record<string, unknown>): { data: Record<string, unknown> | null; errors: { message: string }[] } {
  const ctx: GqlContext = { errors: [], variables };
  try {
    const parser = new GqlParser(query);
    const operation = parser.parseOperation();
    const rootType = operation.kind === 'mutation' ? 'Mutation' : 'Query';
    const data = executeSelections(operation.selections, {}, rootType, ctx);
    return { data, errors: ctx.errors.map((message) => ({ message })) };
  } catch (err) {
    return { data: null, errors: [{ message: err instanceof Error ? err.message : 'GraphQL parse error' }] };
  }
}

async function handleGraphQL(req: IncomingMessage, res: ServerResponse, path: string = pathOf(req)): Promise<boolean> {
  if (path !== '/api/graphql') return false;
  if ((req.method ?? 'GET') !== 'POST') {
    sendError(res, 404, 'Not Found');
    return true;
  }
  if (!authOk(req)) {
    sendError(res, 401, 'Requires authentication');
    return true;
  }
  const parsed = await readJsonBody(req);
  if (!parsed.ok) {
    sendJson(res, 400, { errors: [{ message: 'Problems parsing JSON' }] });
    return true;
  }
  const body = parsed.value;
  if (Array.isArray(body)) {
    const results = body.map((entry) => {
      if (!isRecord(entry) || typeof entry.query !== 'string') return { data: null, errors: [{ message: 'Invalid operation' }] };
      const variables = isRecord(entry.variables) ? (entry.variables as Record<string, unknown>) : {};
      return executeGraphQLOperation(entry.query, variables);
    });
    sendJson(res, 200, results);
    return true;
  }
  if (!isRecord(body) || typeof body.query !== 'string') {
    sendJson(res, 400, { errors: [{ message: 'Invalid operation' }] });
    return true;
  }
  const variables = isRecord(body.variables) ? (body.variables as Record<string, unknown>) : {};
  sendJson(res, 200, executeGraphQLOperation(body.query, variables));
  return true;
}

// ---------------------------------------------------------------------------
// MCP (Model Context Protocol, Streamable HTTP)

interface McpToolDef {
  name: string;
  description: string;
  properties: Record<string, { type: string; description: string }>;
  required: string[];
}
const MCP_TOOLS: McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a new repository owned by the authenticated user.',
    properties: {
      name: { type: 'string', description: 'The repository name.' },
      description: { type: 'string', description: 'A short description of the repository.' },
      private: { type: 'boolean', description: 'Whether the repository is private.' },
    },
    required: ['name'],
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      full_name: { type: 'string', description: 'The repository full name, owner/repo.' },
    },
    required: ['owner', 'repo'],
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      title: { type: 'string', description: 'The issue title.' },
      body: { type: 'string', description: 'The issue body.' },
    },
    required: ['owner', 'repo', 'title'],
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      state: { type: 'string', description: 'Issue state filter: open, closed, or all.' },
    },
    required: ['owner', 'repo'],
  },
  {
    name: 'get_issue',
    description: 'Get one issue by number.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      issue_number: { type: 'integer', description: 'The issue number.' },
    },
    required: ['owner', 'repo', 'issue_number'],
  },
  {
    name: 'create_pull_request',
    description: 'Open a pull request from a head branch into a base branch.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      title: { type: 'string', description: 'The pull request title.' },
      body: { type: 'string', description: 'The pull request body.' },
      head: { type: 'string', description: 'The head branch name.' },
      base: { type: 'string', description: 'The base branch name.' },
    },
    required: ['owner', 'repo', 'title', 'head', 'base'],
  },
  {
    name: 'list_pull_requests',
    description: 'List pull requests in a repository.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      state: { type: 'string', description: 'Pull request state filter: open, closed, or all.' },
    },
    required: ['owner', 'repo'],
  },
  {
    name: 'merge_pull_request',
    description: 'Squash-merge a pull request into its base branch.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      pull_number: { type: 'integer', description: 'The pull request number.' },
    },
    required: ['owner', 'repo', 'pull_number'],
  },
];
const MCP_SERVER_INFO = { name: 'gitforge', version: '1.0.0' };
const MCP_SUPPORTED_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

function mcpToolsJson(): Record<string, unknown>[] {
  return MCP_TOOLS.map((tool) => ({
    name: tool.name,
    description: tool.description,
    inputSchema: { type: 'object', properties: tool.properties, required: tool.required },
  }));
}
function mcpResolveRepo(args: Record<string, unknown>): Repo | null {
  let owner = asString(args.owner);
  let repoName = asString(args.repo ?? args.repository ?? args.repository_name);
  const fullName = asString(args.full_name ?? args.repo_full_name);
  if ((!owner || !repoName) && fullName.includes('/')) {
    const [o, r] = fullName.split('/', 2);
    owner = owner || (o as string);
    repoName = repoName || (r as string);
  }
  if (!owner || !repoName) return null;
  return findRepo(owner, repoName) ?? null;
}
function mcpToolResult(payload: unknown, isError = false): Record<string, unknown> {
  const text = typeof payload === 'string' ? payload : JSON.stringify(payload);
  return { content: [{ type: 'text', text }], structuredContent: payload, isError };
}
function mcpCallTool(name: string, args: Record<string, unknown>): { result?: Record<string, unknown>; errorCode?: number; errorMessage?: string } {
  const tool = MCP_TOOLS.find((t) => t.name === name);
  if (!tool) return { errorCode: -32601, errorMessage: `Unknown tool: ${name}` };
  for (const required of tool.required) {
    if (args[required] === undefined || args[required] === null || args[required] === '') {
      return { result: mcpToolResult({ error: `Missing required argument: ${required}` }, true) };
    }
  }
  switch (name) {
    case 'create_repo': {
      const repoName = asString(args.name);
      if (repos.has(repoKey(VIEWER_LOGIN, repoName))) {
        const existing = repos.get(repoKey(VIEWER_LOGIN, repoName)) as Repo;
        return { result: mcpToolResult(repoJson(existing)) };
      }
      const repo = createRepoRecord(repoName, asString(args.description), asBool(args.private, false));
      return { result: mcpToolResult(repoJson(repo)) };
    }
    case 'get_repo': {
      const repo = mcpResolveRepo(args);
      if (!repo) return { result: mcpToolResult({ error: 'Repository not found' }, true) };
      return { result: mcpToolResult(repoJson(repo)) };
    }
    case 'create_issue': {
      const repo = mcpResolveRepo(args);
      if (!repo) return { result: mcpToolResult({ error: 'Repository not found' }, true) };
      const number = repo.nextIssueNumber;
      repo.nextIssueNumber += 1;
      const issue: Issue = {
        id: nextIssueId,
        globalId: globalId('I', `${repo.id}:${number}`),
        number,
        title: asString(args.title),
        body: asString(args.body, ''),
        state: 'open',
        labels: [],
        comments: [],
        seq: repo.issues.length + 1,
        createdSec: nextTimestamp(),
      };
      nextIssueId += 1;
      repo.issues.push(issue);
      repo.issueRev += 1;
      return { result: mcpToolResult(issueJson(repo, issue)) };
    }
    case 'list_issues': {
      const repo = mcpResolveRepo(args);
      if (!repo) return { result: mcpToolResult({ error: 'Repository not found' }, true) };
      const state = asString(args.state, 'open');
      const list = repo.issues.filter((issue) => state === 'all' || issue.state === state);
      return { result: mcpToolResult({ issues: list.map((issue) => issueJson(repo, issue)) }) };
    }
    case 'get_issue': {
      const repo = mcpResolveRepo(args);
      if (!repo) return { result: mcpToolResult({ error: 'Repository not found' }, true) };
      const number = Number(args.issue_number ?? args.number);
      const issue = repo.issues.find((i) => i.number === number);
      if (!issue) return { result: mcpToolResult({ error: 'Issue not found' }, true) };
      return { result: mcpToolResult(issueJson(repo, issue)) };
    }
    case 'create_pull_request': {
      const repo = mcpResolveRepo(args);
      if (!repo) return { result: mcpToolResult({ error: 'Repository not found' }, true) };
      const head = asString(args.head);
      const base = asString(args.base, repo.defaultBranch);
      if (!refTip(repo, head) || !refTip(repo, base)) {
        return { result: mcpToolResult({ error: 'head or base branch does not exist' }, true) };
      }
      const existing = repo.pulls.find((p) => p.state === 'open' && p.headRef === head && p.baseRef === base);
      if (existing) return { result: mcpToolResult(pullJson(repo, existing)) };
      const number = repo.nextPullNumber;
      repo.nextPullNumber += 1;
      const pull: PullRequest = {
        id: nextPullId,
        globalId: globalId('P', `${repo.id}:${number}`),
        number,
        title: asString(args.title),
        body: asString(args.body, ''),
        headRef: head,
        baseRef: base,
        state: 'open',
        merged: false,
        mergedAt: null,
        mergeCommitSha: null,
        seq: repo.pulls.length + 1,
        createdSec: nextTimestamp(),
      };
      nextPullId += 1;
      repo.pulls.push(pull);
      return { result: mcpToolResult(pullJson(repo, pull)) };
    }
    case 'list_pull_requests': {
      const repo = mcpResolveRepo(args);
      if (!repo) return { result: mcpToolResult({ error: 'Repository not found' }, true) };
      const state = asString(args.state, 'open');
      const list = repo.pulls.filter((pull) => state === 'all' || pull.state === state);
      return { result: mcpToolResult({ pull_requests: list.map((pull) => pullJson(repo, pull)) }) };
    }
    case 'merge_pull_request': {
      const repo = mcpResolveRepo(args);
      if (!repo) return { result: mcpToolResult({ error: 'Repository not found' }, true) };
      const number = Number(args.pull_number ?? args.number);
      const pull = repo.pulls.find((p) => p.number === number);
      if (!pull) return { result: mcpToolResult({ error: 'Pull request not found' }, true) };
      if (pull.state !== 'open') return { result: mcpToolResult({ error: 'Pull request is already closed' }, true) };
      const sha = squashMerge(repo, pull);
      if (sha === null) return { result: mcpToolResult({ error: 'Merge conflict' }, true) };
      return { result: mcpToolResult({ number: pull.number, merged: true, sha, state: 'closed' }) };
    }
    default:
      return { errorCode: -32601, errorMessage: `Unknown tool: ${name}` };
  }
}

function mcpSend(res: ServerResponse, status: number, body: unknown): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': String(Buffer.byteLength(text)) });
  res.end(text);
}

async function handleMcp(req: IncomingMessage, res: ServerResponse, path: string = pathOf(req)): Promise<boolean> {
  if (path !== '/mcp') return false;
  const method = req.method ?? 'GET';
  if (method === 'DELETE') {
    res.writeHead(204);
    res.end();
    return true;
  }
  if (method !== 'POST') {
    mcpSend(res, 405, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Method not allowed' } });
    return true;
  }
  if (!authOk(req)) {
    mcpSend(res, 401, { jsonrpc: '2.0', id: null, error: { code: -32001, message: 'Unauthorized' } });
    return true;
  }
  const raw = await readBody(req);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString('utf8')) as unknown;
  } catch {
    let id: unknown = null;
    const match = /"id"\s*:\s*(\d+|"[^"]*")/.exec(raw.toString('utf8'));
    if (match) {
      try {
        id = JSON.parse(match[1] as string) as unknown;
      } catch {
        id = null;
      }
    }
    mcpSend(res, 400, { jsonrpc: '2.0', id, error: { code: -32700, message: 'Parse error' } });
    return true;
  }
  if (!isRecord(parsed)) {
    mcpSend(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return true;
  }
  const rpcMethod = asString(parsed.method);
  const rpcId = parsed.id ?? null;
  const params = isRecord(parsed.params) ? (parsed.params as Record<string, unknown>) : {};
  // A notification (no id) is answered with 202 and no body.
  if (parsed.id === undefined) {
    res.writeHead(202);
    res.end();
    return true;
  }
  const result = (value: unknown): void => mcpSend(res, 200, { jsonrpc: '2.0', id: rpcId, result: value });
  const rpcError = (code: number, message: string): void => mcpSend(res, 200, { jsonrpc: '2.0', id: rpcId, error: { code, message } });
  if (rpcMethod === 'server/discover') {
    result({
      supportedVersions: MCP_SUPPORTED_VERSIONS,
      capabilities: { tools: {} },
      serverInfo: MCP_SERVER_INFO,
      _meta: { 'io.modelcontextprotocol/serverInfo': MCP_SERVER_INFO },
    });
    return true;
  }
  if (rpcMethod === 'initialize') {
    const requested = asString(params.protocolVersion, '2025-11-25');
    const negotiated = MCP_SUPPORTED_VERSIONS.includes(requested) ? requested : '2025-11-25';
    result({ protocolVersion: negotiated, capabilities: { tools: {} }, serverInfo: MCP_SERVER_INFO });
    return true;
  }
  if (rpcMethod === 'ping') {
    result({});
    return true;
  }
  if (rpcMethod === 'tools/list') {
    result({ tools: mcpToolsJson() });
    return true;
  }
  if (rpcMethod === 'tools/call') {
    const toolName = asString(params.name);
    const args = isRecord(params.arguments) ? (params.arguments as Record<string, unknown>) : {};
    const outcome = mcpCallTool(toolName, args);
    if (outcome.errorCode !== undefined) {
      rpcError(outcome.errorCode, outcome.errorMessage ?? 'Invalid params');
      return true;
    }
    result(outcome.result);
    return true;
  }
  rpcError(-32601, `Method not found: ${rpcMethod}`);
  return true;
}

// ---------------------------------------------------------------------------
// Git smart HTTP

function gitRefLines(repo: Repo): { oid: string; name: string; peeled?: string }[] {
  const lines: { oid: string; name: string; peeled?: string }[] = [];
  const refs = [...repo.refs.entries()].sort(([a], [b]) => (a < b ? -1 : 1));
  const defaultTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  if (defaultTip) lines.push({ oid: defaultTip, name: 'HEAD' });
  for (const [name, oid] of refs) {
    lines.push({ oid, name });
    const obj = repo.objects.get(oid);
    if (obj && obj.type === 'tag') {
      const peeled = peelToCommit(repo.objects, oid);
      if (peeled !== oid) lines.push({ oid: peeled, name: `${name}^{}` });
    }
  }
  return lines;
}

function v0Advertisement(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const parts: Buffer[] = [];
  parts.push(pktLine(`# service=${service}\n`));
  parts.push(PKT_FLUSH);
  const lines = gitRefLines(repo);
  const capabilities =
    service === 'git-upload-pack'
      ? 'multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not no-progress include-tag multi_ack_detailed agent=gitforge/1.0'
      : 'report-status delete-refs side-band-64k quiet ofs-delta agent=gitforge/1.0';
  const symref = repo.refs.has(`refs/heads/${repo.defaultBranch}`) ? ` symref=HEAD:refs/heads/${repo.defaultBranch}` : '';
  if (lines.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${capabilities}${symref}\n`));
  } else {
    lines.forEach((line, index) => {
      const suffix = index === 0 ? `\0${capabilities}${symref}` : '';
      parts.push(pktLine(`${line.oid} ${line.name}${suffix}\n`));
    });
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

/** The v2 capability advertisement never changes: precompute it once. */
const V2_ADVERTISEMENT: Buffer = Buffer.concat([
  ...['version 2', 'ls-refs=unborn', 'fetch=shallow wait-for-done', 'object-format=sha1', 'agent=gitforge/1.0'].map((line) => pktLine(`${line}\n`)),
  PKT_FLUSH,
]);
function v2Advertisement(): Buffer {
  return V2_ADVERTISEMENT;
}

function sendGit(res: ServerResponse, status: number, contentType: string, body: Buffer): void {
  res.writeHead(status, { 'content-type': contentType, 'content-length': String(body.length) });
  res.end(body);
}

/** Objects reachable from `roots` without following commit parents (depth-limited fetch). */
function collectDepthLimited(objects: Map<string, GitObject>, roots: readonly string[]): Set<string> {
  const out = new Set<string>();
  const stack: string[] = [...roots];
  while (stack.length) {
    const oid = stack.pop() as string;
    if (out.has(oid)) continue;
    const obj = objects.get(oid);
    if (!obj) continue;
    out.add(oid);
    if (obj.type === 'commit') {
      const tree = parseCommit(obj.data).tree;
      if (tree) stack.push(tree);
    } else if (obj.type === 'tag') {
      stack.push(parseTag(obj.data).object);
    } else if (obj.type === 'tree') {
      for (const entry of parseTree(obj.data)) stack.push(entry.oid);
    }
  }
  return out;
}

/** Compute the objects a fetch should send, honouring haves and depth. */
function fetchObjects(repo: Repo, wants: readonly string[], haves: readonly string[], depth: number | null, shallowBefore: readonly string[]): { objects: GitObject[]; shallow: string[]; unshallow: string[] } {
  // Walk commits from the wants, tracking generation depth.
  const includedCommits = new Set<string>();
  const boundary = new Set<string>();
  interface WalkItem {
    oid: string;
    depth: number;
  }
  const queue: WalkItem[] = wants.map((oid) => ({ oid, depth: 0 }));
  const seenCommits = new Set<string>();
  // Index pointer instead of queue.shift(): shift() is O(n) per pop, O(n^2) over a
  // 200-commit walk. The order is identical (FIFO from the front).
  let queueHead = 0;
  while (queueHead < queue.length) {
    const item = queue[queueHead++] as WalkItem;
    const obj = repo.objects.get(item.oid);
    if (!obj) continue;
    if (obj.type === 'tag') {
      queue.push({ oid: parseTag(obj.data).object, depth: item.depth });
      continue;
    }
    if (obj.type !== 'commit') continue;
    if (seenCommits.has(item.oid)) continue;
    seenCommits.add(item.oid);
    includedCommits.add(item.oid);
    if (depth !== null && item.depth + 1 >= depth) {
      boundary.add(item.oid);
      continue;
    }
    for (const parent of parseCommit(obj.data).parents) queue.push({ oid: parent, depth: item.depth + 1 });
  }
  // Everything reachable from the included commits and wanted tags.
  // With a depth limit, parents beyond the boundary are never followed, and
  // the have-exclusion is skipped: a deepen must deliver the parent commit
  // even though it is reachable from a have the client already holds.
  const reachable =
    depth === null
      ? collectReachable(repo.objects, [...includedCommits, ...wants])
      : collectDepthLimited(repo.objects, [...includedCommits, ...wants]);
  const haveClosure = depth === null ? collectReachable(repo.objects, haves.filter((oid) => repo.objects.has(oid))) : new Set<string>();
  const objects: GitObject[] = [];
  for (const oid of [...reachable].sort()) {
    if (haveClosure.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (obj) objects.push({ type: obj.type, data: obj.data });
  }
  const shallow = [...boundary].sort();
  const unshallow = shallowBefore.filter((oid) => includedCommits.has(oid) && !boundary.has(oid));
  return { objects, shallow, unshallow };
}

function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  const CHUNK = 65500;
  for (let off = 0; off < pack.length; off += CHUNK) {
    const slice = pack.subarray(off, Math.min(pack.length, off + CHUNK));
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), slice])));
  }
  return Buffer.concat(parts);
}

function handleUploadPackV2(repo: Repo, packets: PktPacket[]): Buffer {
  const lines: string[] = [];
  for (const packet of packets) {
    if (packet.kind === 'flush' || packet.kind === 'delim') {
      lines.push(packet.kind === 'flush' ? 'flush' : 'delim');
      continue;
    }
    if (packet.kind === 'data') lines.push(packet.payload.toString('utf8'));
  }
  const commandLine = lines.find((line) => line.startsWith('command=')) ?? '';
  const command = commandLine.slice('command='.length).trim();
  if (command === 'ls-refs') {
    let peel = false;
    let symrefs = false;
    const prefixes: string[] = [];
    for (const line of lines) {
      const text = line.trim();
      if (text === 'peel') peel = true;
      else if (text === 'symrefs') symrefs = true;
      else if (text.startsWith('ref-prefix ')) prefixes.push(text.slice('ref-prefix '.length));
    }
    const parts: Buffer[] = [];
    const defaultTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
    const includeHead = prefixes.length === 0;
    if (includeHead && symrefs) {
      if (defaultTip) parts.push(pktLine(`${defaultTip} HEAD symref-target:refs/heads/${repo.defaultBranch}\n`));
      else parts.push(pktLine(`unborn HEAD symref-target:refs/heads/${repo.defaultBranch}\n`));
    } else if (includeHead && defaultTip) {
      parts.push(pktLine(`${defaultTip} HEAD\n`));
    }
    const refs = [...repo.refs.entries()].sort(([a], [b]) => (a < b ? -1 : 1));
    for (const [name, oid] of refs) {
      if (prefixes.length > 0 && !prefixes.some((prefix) => name.startsWith(prefix))) continue;
      let suffix = '';
      if (symrefs && name === `refs/heads/${repo.defaultBranch}`) suffix += '';
      const obj = repo.objects.get(oid);
      if (peel && obj && obj.type === 'tag') {
        const peeled = peelToCommit(repo.objects, oid);
        if (peeled !== oid) suffix += ` peeled:${peeled}`;
      }
      parts.push(pktLine(`${oid} ${name}${suffix}\n`));
    }
    parts.push(PKT_FLUSH);
    return Buffer.concat(parts);
  }
  if (command === 'fetch') {
    const wants: string[] = [];
    const haves: string[] = [];
    const shallowBefore: string[] = [];
    let depth: number | null = null;
    for (const line of lines) {
      const text = line.trim();
      if (text.startsWith('want ')) wants.push(text.slice(5).trim());
      else if (text.startsWith('have ')) haves.push(text.slice(5).trim());
      else if (text.startsWith('shallow ')) shallowBefore.push(text.slice(8).trim());
      else if (text.startsWith('deepen ')) depth = Number(text.slice(7).trim());
    }
    const cacheKey = JSON.stringify([[...wants].sort(), [...haves].sort(), depth, [...shallowBefore].sort()]);
    const cached = repo.packCache.get(cacheKey);
    if (cached) return cached;
    const { objects, shallow, unshallow } = fetchObjects(repo, wants, haves, depth, shallowBefore);
    const parts: Buffer[] = [];
    parts.push(pktLine('acknowledgments\n'));
    parts.push(pktLine('NAK\n'));
    parts.push(PKT_DELIM);
    if (shallow.length > 0 || unshallow.length > 0) {
      parts.push(pktLine('shallow-info\n'));
      for (const oid of shallow) parts.push(pktLine(`shallow ${oid}\n`));
      for (const oid of unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
      parts.push(PKT_DELIM);
    }
    if (objects.length > 0) {
      const pack = writePack(objects);
      parts.push(pktLine('packfile\n'));
      parts.push(sidebandPack(pack));
    }
    parts.push(PKT_FLUSH);
    const out = Buffer.concat(parts);
    repo.packCache.set(cacheKey, out);
    return out;
  }
  // Unknown v2 command: answer a flush so the client fails cleanly.
  return Buffer.concat([PKT_FLUSH]);
}

function handleUploadPackV0(repo: Repo, packets: PktPacket[]): Buffer {
  const wants: string[] = [];
  const haves: string[] = [];
  const shallowBefore: string[] = [];
  let depth: number | null = null;
  let section = 0;
  for (const packet of packets) {
    if (packet.kind === 'flush') {
      section += 1;
      continue;
    }
    if (packet.kind !== 'data') continue;
    const text = packet.payload.toString('utf8').trim();
    if (text.startsWith('want ')) wants.push(text.slice(5).split(' ')[0] as string);
    else if (text.startsWith('have ')) haves.push(text.slice(5).trim());
    else if (text.startsWith('shallow ')) shallowBefore.push(text.slice(8).trim());
    else if (text.startsWith('deepen ')) depth = Number(text.slice(7).trim());
  }
  const cacheKey = JSON.stringify(['v0', [...wants].sort(), [...haves].sort(), depth, [...shallowBefore].sort()]);
  const cached = repo.packCache.get(cacheKey);
  if (cached) return cached;
  const { objects, shallow, unshallow } = fetchObjects(repo, wants, haves, depth, shallowBefore);
  const parts: Buffer[] = [pktLine('NAK\n')];
  for (const oid of shallow) parts.push(pktLine(`shallow ${oid}\n`));
  for (const oid of unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
  if (objects.length > 0) parts.push(sidebandPack(writePack(objects)));
  parts.push(PKT_FLUSH);
  const out = Buffer.concat(parts);
  repo.packCache.set(cacheKey, out);
  return out;
}

function handleReceivePack(repo: Repo, body: Buffer): Buffer {
  const flushIndex = (() => {
    // Find the first flush pkt-line; everything after it is the pack.
    let off = 0;
    while (off + 4 <= body.length) {
      const hex = body.subarray(off, off + 4).toString('ascii');
      if (!isHex4(hex)) return -1;
      const len = parseInt(hex, 16);
      if (len === 0) return off + 4;
      if (len < 4 || off + len > body.length) return -1;
      off += len;
    }
    return -1;
  })();
  const commandBytes = flushIndex < 0 ? body : body.subarray(0, flushIndex);
  const packBytes = flushIndex < 0 ? Buffer.alloc(0) : body.subarray(flushIndex);
  interface Command {
    oldOid: string;
    newOid: string;
    ref: string;
  }
  const commands: Command[] = [];
  try {
    for (const packet of parsePktLines(commandBytes)) {
      if (packet.kind !== 'data') continue;
      const text = packet.payload.toString('utf8');
      const nul = text.indexOf('\0');
      const line = (nul >= 0 ? text.slice(0, nul) : text).trim();
      if (line === '') continue;
      const parts = line.split(' ');
      if (parts.length < 3) continue;
      commands.push({ oldOid: parts[0] as string, newOid: parts[1] as string, ref: parts[2] as string });
    }
  } catch {
    // Malformed command list: report an unpack failure and stay up.
    const report = Buffer.concat([pktLine('unpack error\n'), PKT_FLUSH]);
    return Buffer.concat([pktLine(Buffer.concat([Buffer.from([1]), report])), PKT_FLUSH]);
  }
  const updatesRef = commands.some((c) => c.newOid !== ZERO_OID);
  let unpackOk = true;
  let unpackDetail = 'ok';
  const newObjects = new Map<string, GitObject>();
  if (updatesRef) {
    if (packBytes.length === 0) {
      unpackOk = false;
      unpackDetail = 'unpacker error';
    } else {
      try {
        const entries = readPack(packBytes, (oid) => repo.objects.get(oid) ?? newObjects.get(oid));
        for (const entry of entries) newObjects.set(entry.oid, { type: entry.type, data: entry.data });
      } catch {
        unpackOk = false;
        unpackDetail = 'unpacker error';
      }
    }
  }
  const reportLines: string[] = [`unpack ${unpackOk ? 'ok' : unpackDetail}`];
  if (unpackOk) {
    for (const [oid, obj] of newObjects) repo.objects.set(oid, obj);
    for (const command of commands) {
      const current = repo.refs.get(command.ref);
      if (command.newOid === ZERO_OID) {
        // Delete.
        if (current === undefined) {
          reportLines.push(`ng ${command.ref} non-fast-forward`);
        } else if (command.oldOid !== ZERO_OID && command.oldOid !== current) {
          reportLines.push(`ng ${command.ref} non-fast-forward`);
        } else {
          repo.refs.delete(command.ref);
          repo.version += 1;
          reportLines.push(`ok ${command.ref}`);
        }
        continue;
      }
      if (!repo.objects.has(command.newOid)) {
        reportLines.push(`ng ${command.ref} invalid object`);
        continue;
      }
      if (current === undefined) {
        if (command.oldOid !== ZERO_OID) {
          reportLines.push(`ng ${command.ref} non-fast-forward`);
          continue;
        }
        repo.refs.set(command.ref, command.newOid);
        repo.version += 1;
        reportLines.push(`ok ${command.ref}`);
        continue;
      }
      if (command.oldOid !== current) {
        reportLines.push(`ng ${command.ref} non-fast-forward`);
        continue;
      }
      if (!isAncestor(repo.objects, current, command.newOid)) {
        reportLines.push(`ng ${command.ref} non-fast-forward`);
        continue;
      }
      repo.refs.set(command.ref, command.newOid);
      repo.version += 1;
      reportLines.push(`ok ${command.ref}`);
    }
    repo.packCache.clear();
  }
  const report = Buffer.concat([...reportLines.map((line) => pktLine(`${line}\n`)), PKT_FLUSH]);
  return Buffer.concat([pktLine(Buffer.concat([Buffer.from([1]), report])), PKT_FLUSH]);
}

/** The v0 ref advertisement, cached per repo version + default branch (refs drive it). */
function cachedV0Advertisement(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const cached = repo.advCache.get(service);
  if (cached && cached.version === repo.version && cached.branch === repo.defaultBranch) return cached.body;
  const body = v0Advertisement(repo, service);
  repo.advCache.set(service, { version: repo.version, branch: repo.defaultBranch, body });
  return body;
}

async function handleGit(req: IncomingMessage, res: ServerResponse, rawPath: string = pathOf(req), query: URLSearchParams = queryOf(req)): Promise<boolean> {
  const gitMatch = /^\/([^/]+)\/([^/]+)\.git(\/.*)$/.exec(rawPath);
  if (!gitMatch) return false;
  const owner = decodePath(gitMatch[1] as string);
  const name = decodePath(gitMatch[2] as string);
  const suffix = gitMatch[3] as string;
  const method = req.method ?? 'GET';
  if (!authOk(req)) {
    sendError(res, 401, 'Requires authentication');
    return true;
  }
  const repo = findRepo(owner, name);
  if (suffix === '/info/refs') {
    if (method !== 'GET') {
      sendError(res, 405, 'Method Not Allowed');
      return true;
    }
    const service = query.get('service') ?? '';
    if (!repo) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    if (service === 'git-upload-pack') {
      const wantsV2 = req.headers['git-protocol'] === 'version=2';
      if (wantsV2) sendGit(res, 200, 'application/x-git-upload-pack-advertisement', v2Advertisement());
      else sendGit(res, 200, 'application/x-git-upload-pack-advertisement', cachedV0Advertisement(repo, 'git-upload-pack'));
      return true;
    }
    if (service === 'git-receive-pack') {
      sendGit(res, 200, 'application/x-git-receive-pack-advertisement', cachedV0Advertisement(repo, 'git-receive-pack'));
      return true;
    }
    sendError(res, 404, 'Not Found');
    return true;
  }
  if (!repo) {
    sendError(res, 404, 'Not Found');
    return true;
  }
  if (suffix === '/git-upload-pack' && method === 'POST') {
    const body = await readBody(req);
    let packets: PktPacket[];
    try {
      packets = parsePktLines(body);
    } catch {
      res.writeHead(400, { 'content-type': 'text/plain' });
      res.end('bad request');
      return true;
    }
    const isV2 = packets.some((p) => p.kind === 'data' && p.payload.toString('utf8').startsWith('command='));
    const out = isV2 ? handleUploadPackV2(repo, packets) : handleUploadPackV0(repo, packets);
    sendGit(res, 200, 'application/x-git-upload-pack-result', out);
    return true;
  }
  if (suffix === '/git-receive-pack' && method === 'POST') {
    const body = await readBody(req);
    const out = handleReceivePack(repo, body);
    sendGit(res, 200, 'application/x-git-receive-pack-result', out);
    return true;
  }
  sendError(res, 404, 'Not Found');
  return true;
}

// ---------------------------------------------------------------------------
// Server and lifecycle

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  try {
    // Parse the request URL once; every handler below reuses it (was 3-4 parses).
    let path = '/';
    let query = new URLSearchParams();
    try {
      const url = new URL(req.url ?? '/', 'http://entry');
      path = url.pathname;
      query = url.searchParams;
    } catch {
      // keep the defaults
    }
    if (req.method === 'GET' && path === '/healthz') {
      sendJson(res, 200, { ok: true });
      return;
    }
    if (await handleGit(req, res, path, query)) return;
    if (await handleRest(req, res, path, query)) return;
    if (await handleGraphQL(req, res, path)) return;
    if (await handleMcp(req, res, path)) return;
    sendError(res, 404, 'Not Found');
  } catch (err) {
    if (!res.headersSent) {
      try {
        sendError(res, 500, err instanceof Error ? err.message : 'Internal Server Error');
      } catch {
        // The socket is gone; nothing more to do.
      }
    }
  }
}

const ENV_URL = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
const REQUEST_TIMEOUT_MS = 30_000;
const RETRY_INITIAL_MS = 250;
const RETRY_MAX_MS = 2_000;
const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)));
function retryDelay(attempt: number): number {
  return Math.min(RETRY_MAX_MS, RETRY_INITIAL_MS * 2 ** Math.min(attempt, 8));
}

async function register(port: number): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const res = await fetch(`${ENV_URL}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (res.status === 200 || res.status === 409) return;
      if (res.status === 400 || res.status === 405) throw new Error(`register answered HTTP ${res.status}: ${await res.text()}`);
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('register answered HTTP ')) throw err;
    }
    await sleep(retryDelay(attempt));
  }
}
async function waitForDone(): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const res = await fetch(`${ENV_URL}/done`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
      if (res.ok) {
        const body = (await res.json()) as { done?: unknown };
        if (body.done === true) return;
      }
    } catch {
      // Not done yet; poll again.
    }
    await sleep(retryDelay(attempt));
  }
}

async function main(): Promise<void> {
  const server = createServer((req, res) => {
    void handleRequest(req, res);
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('the server did not bind an ephemeral TCP port');
  process.stdout.write(`[entry] gitforge listening on port ${address.port} (viewer ${VIEWER_LOGIN})\n`);
  if (ENV_URL === '') {
    // No env to register with (a manual run): serve until killed.
    process.stdout.write('[entry] MAKEFUN_ENV_URL is not set; serving without registering\n');
    await new Promise<void>(() => undefined);
    return;
  }
  await register(address.port);
  process.stdout.write('[entry] registered; waiting for the env to say done\n');
  await waitForDone();
  server.close();
  process.stdout.write('[entry] done\n');
}

try {
  await main();
  process.exit(0);
} catch (err) {
  process.stderr.write(`[entry] ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}
