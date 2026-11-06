/* eslint-disable functype/prefer-either, functype/prefer-option --
 * Imperative SQLite storage adapter bridging bun:sqlite and node:sqlite behind a unified
 * synchronous API. Public callers in ArcticShiftClient wrap calls in Try/Option as needed.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs"
import { createRequire } from "node:module"
import { homedir } from "node:os"
import { dirname, join, resolve } from "node:path"

import type {
  Page,
  PostComments,
  RedditApiCommentTreeData,
  RedditApiPostData,
  RedditComment,
  RedditPost,
} from "../types"
import type { QuarantinedItemRecord } from "../utils/content-scanner"
import { scanContent } from "../utils/content-scanner"
import { normalizeSubreddit, normalizeThingId, normalizeUsername } from "../utils/reddit-identifiers"
import { parseCommentData, parsePostData } from "./reddit-parsers"

const DEFAULT_ARCHIVE_DIR = process.env["REDDIT_ARCHIVE_DIR"] ?? join(homedir(), "dev", "reddit")
const DEFAULT_DB_PATH = join(DEFAULT_ARCHIVE_DIR, "reddit-archive.db")
const DEFAULT_SCAN_REPORT_PATH = join(DEFAULT_ARCHIVE_DIR, "scan-report.json")

type SqlParam = string | number | null

type SqlStatement = {
  readonly run: (...params: SqlParam[]) => unknown
  readonly get: (...params: SqlParam[]) => Record<string, unknown> | undefined
  readonly all: (...params: SqlParam[]) => ReadonlyArray<Record<string, unknown>>
}

type SqlDatabase = {
  readonly exec: (sql: string) => void
  readonly prepare: (sql: string) => SqlStatement
  readonly close: () => void
}

export type SubredditSyncStats = {
  readonly subreddit: string
  readonly lastPostUtc: number
  readonly lastCommentUtc: number
  readonly postCount: number
  readonly commentCount: number
  readonly quarantinedCount: number
  readonly updatedAt: string
}

export type ArchiveStatusSummary = {
  readonly dbPath: string
  readonly scanReportPath: string
  readonly runtime: "bun:sqlite" | "node:sqlite"
  readonly subreddits: readonly SubredditSyncStats[]
  readonly totalPosts: number
  readonly totalComments: number
  readonly totalQuarantined: number
}

export type IngestBatchSummary = {
  readonly ingested: number
  readonly quarantined: number
  readonly newestUtc: number
  readonly flaggedItems: readonly QuarantinedItemRecord[]
}

const requireModule = createRequire(import.meta.url)

function openSqlDatabase(dbPath: string): { readonly db: SqlDatabase; readonly runtime: "bun:sqlite" | "node:sqlite" } {
  mkdirSync(dirname(dbPath), { recursive: true })

  // Prefer Bun's native C-speed SQLite driver when running under Bun; fall back to Node 22+/25+ node:sqlite.
  const isBun = typeof (globalThis as { readonly Bun?: unknown }).Bun !== "undefined"
  if (isBun) {
    const bunSqlite = requireModule("bun:sqlite") as {
      readonly Database: new (path: string) => {
        readonly exec: (sql: string) => void
        readonly query: (sql: string) => {
          readonly run: (...params: SqlParam[]) => unknown
          readonly get: (...params: SqlParam[]) => Record<string, unknown> | null
          readonly all: (...params: SqlParam[]) => ReadonlyArray<Record<string, unknown>>
        }
        readonly close: () => void
      }
    }
    const raw = new bunSqlite.Database(dbPath)
    return {
      runtime: "bun:sqlite",
      db: {
        exec: (sql: string) => raw.exec(sql),
        prepare: (sql: string): SqlStatement => {
          const stmt = raw.query(sql)
          return {
            run: (...params: SqlParam[]) => stmt.run(...params),
            get: (...params: SqlParam[]) => stmt.get(...params) ?? undefined,
            all: (...params: SqlParam[]) => stmt.all(...params),
          }
        },
        close: () => raw.close(),
      },
    }
  }

  const nodeSqlite = requireModule("node:sqlite") as {
    readonly DatabaseSync: new (path: string) => {
      readonly exec: (sql: string) => void
      readonly prepare: (sql: string) => SqlStatement
      readonly close: () => void
    }
  }
  const raw = new nodeSqlite.DatabaseSync(dbPath)
  return {
    runtime: "node:sqlite",
    db: {
      exec: (sql: string) => raw.exec(sql),
      prepare: (sql: string) => raw.prepare(sql),
      close: () => raw.close(),
    },
  }
}

// Convert user search input into a safe SQLite FTS5 query string so punctuation like "WPC-95"
// or "TIP102/TIP36C" never triggers an FTS5 syntax error.
export function toSafeFtsQuery(rawQuery: string): string {
  const trimmed = rawQuery.trim()
  if (trimmed === "") return '""'

  // Extract quoted phrases and individual alphanumeric tokens
  const phrases: string[] = []
  const withoutQuotes = trimmed.replace(/"([^"]+)"/g, (_match, phrase: string) => {
    const clean = phrase.replace(/"/g, "").trim()
    if (clean !== "") phrases.push(`"${clean}"`)
    return " "
  })

  const tokens = withoutQuotes
    .split(/[^A-Za-z0-9_]+/)
    .map((t) => t.trim())
    .filter((t) => t !== "" && !["AND", "OR", "NOT"].includes(t.toUpperCase()))
    .map((t) => `"${t}"*`)

  const combined = [...phrases, ...tokens]
  return combined.length > 0 ? combined.join(" AND ") : `"${trimmed.replace(/"/g, "")}"`
}

export class LocalArchiveStore {
  readonly dbPath: string
  readonly scanReportPath: string
  readonly runtime: "bun:sqlite" | "node:sqlite"
  private readonly db: SqlDatabase

  constructor(dbPath?: string, scanReportPath?: string) {
    this.dbPath = resolve(dbPath ?? process.env["REDDIT_ARCHIVE_DB"] ?? DEFAULT_DB_PATH)
    this.scanReportPath = resolve(scanReportPath ?? process.env["REDDIT_SCAN_REPORT"] ?? DEFAULT_SCAN_REPORT_PATH)
    const opened = openSqlDatabase(this.dbPath)
    this.db = opened.db
    this.runtime = opened.runtime
    this.initSchema()
  }

  private initSchema(): void {
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = NORMAL;

      CREATE TABLE IF NOT EXISTS posts (
        id TEXT PRIMARY KEY,
        subreddit TEXT NOT NULL,
        subreddit_lower TEXT NOT NULL,
        author TEXT NOT NULL,
        author_lower TEXT NOT NULL,
        title TEXT NOT NULL,
        selftext TEXT NOT NULL,
        url TEXT NOT NULL,
        permalink TEXT NOT NULL,
        created_utc INTEGER NOT NULL,
        raw_json TEXT NOT NULL,
        quarantined INTEGER NOT NULL DEFAULT 0,
        flag_reasons TEXT NOT NULL DEFAULT '[]'
      );

      CREATE INDEX IF NOT EXISTS idx_posts_sub_created ON posts(subreddit_lower, created_utc DESC);
      CREATE INDEX IF NOT EXISTS idx_posts_author_created ON posts(author_lower, created_utc DESC);

      CREATE TABLE IF NOT EXISTS comments (
        id TEXT PRIMARY KEY,
        link_id TEXT NOT NULL,
        parent_id TEXT NOT NULL,
        subreddit TEXT NOT NULL,
        subreddit_lower TEXT NOT NULL,
        author TEXT NOT NULL,
        author_lower TEXT NOT NULL,
        body TEXT NOT NULL,
        submission_title TEXT NOT NULL,
        permalink TEXT NOT NULL,
        created_utc INTEGER NOT NULL,
        raw_json TEXT NOT NULL,
        quarantined INTEGER NOT NULL DEFAULT 0,
        flag_reasons TEXT NOT NULL DEFAULT '[]'
      );

      CREATE INDEX IF NOT EXISTS idx_comments_link_id ON comments(link_id, created_utc ASC);
      CREATE INDEX IF NOT EXISTS idx_comments_sub_created ON comments(subreddit_lower, created_utc DESC);
      CREATE INDEX IF NOT EXISTS idx_comments_author_created ON comments(author_lower, created_utc DESC);

      CREATE TABLE IF NOT EXISTS sync_state (
        subreddit_lower TEXT PRIMARY KEY,
        subreddit TEXT NOT NULL,
        last_post_utc INTEGER NOT NULL DEFAULT 0,
        last_comment_utc INTEGER NOT NULL DEFAULT 0,
        post_count INTEGER NOT NULL DEFAULT 0,
        comment_count INTEGER NOT NULL DEFAULT 0,
        quarantined_count INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL
      );

      CREATE VIRTUAL TABLE IF NOT EXISTS posts_fts USING fts5(
        id UNINDEXED,
        subreddit_lower UNINDEXED,
        title,
        selftext,
        tokenize = 'porter unicode61'
      );

      CREATE VIRTUAL TABLE IF NOT EXISTS comments_fts USING fts5(
        id UNINDEXED,
        subreddit_lower UNINDEXED,
        author_lower UNINDEXED,
        body,
        submission_title,
        tokenize = 'porter unicode61'
      );

      -- Reserved metadata table for optional future sqlite-vec hybrid embeddings
      CREATE TABLE IF NOT EXISTS vector_index_meta (
        item_type TEXT NOT NULL,
        item_id TEXT NOT NULL,
        model_name TEXT NOT NULL,
        dimensions INTEGER NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (item_type, item_id)
      );
    `)
  }

  hasSubreddit(subreddit: string): boolean {
    const subLower = normalizeSubreddit(subreddit).toLowerCase()
    if (subLower === "") return false
    const row = this.db
      .prepare("SELECT post_count, comment_count FROM sync_state WHERE subreddit_lower = ?")
      .get(subLower)
    if (row === undefined) return false
    return Number(row["post_count"] ?? 0) > 0 || Number(row["comment_count"] ?? 0) > 0
  }

  getSubredditSyncState(subreddit: string): SubredditSyncStats | undefined {
    const subLower = normalizeSubreddit(subreddit).toLowerCase()
    const row = this.db.prepare("SELECT * FROM sync_state WHERE subreddit_lower = ?").get(subLower)
    if (row === undefined) return undefined
    return {
      subreddit: String(row["subreddit"]),
      lastPostUtc: Number(row["last_post_utc"]),
      lastCommentUtc: Number(row["last_comment_utc"]),
      postCount: Number(row["post_count"]),
      commentCount: Number(row["comment_count"]),
      quarantinedCount: Number(row["quarantined_count"]),
      updatedAt: String(row["updated_at"]),
    }
  }

  upsertPosts(subreddit: string, rawPosts: readonly RedditApiPostData[]): IngestBatchSummary {
    const cleanSub = normalizeSubreddit(subreddit)
    const subLower = cleanSub.toLowerCase()
    const insertPost = this.db.prepare(`
      INSERT OR REPLACE INTO posts (
        id, subreddit, subreddit_lower, author, author_lower, title, selftext, url, permalink, created_utc, raw_json, quarantined, flag_reasons
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    const deleteFts = this.db.prepare("DELETE FROM posts_fts WHERE id = ?")
    const insertFts = this.db.prepare(
      "INSERT INTO posts_fts (id, subreddit_lower, title, selftext) VALUES (?, ?, ?, ?)",
    )

    let newestUtc = 0
    let quarantinedCount = 0
    const flaggedItems: QuarantinedItemRecord[] = []

    this.db.exec("BEGIN TRANSACTION")
    try {
      for (const post of rawPosts) {
        const id = normalizeThingId(post.id)
        const title = post.title ?? ""
        const selftext = post.selftext ?? ""
        const scan = scanContent(`${title}\n${selftext}\n${post.url ?? ""}`)
        const isQuarantined = scan.quarantined ? 1 : 0
        const postSub = post.subreddit || cleanSub
        const postSubLower = postSub.toLowerCase()
        const createdUtc = Math.trunc(Number(post.created_utc ?? 0))
        if (createdUtc > newestUtc) newestUtc = createdUtc

        insertPost.run(
          id,
          postSub,
          postSubLower,
          post.author ?? "[deleted]",
          (post.author ?? "[deleted]").toLowerCase(),
          title,
          selftext,
          post.url ?? "",
          post.permalink ?? `/r/${postSub}/comments/${id}/`,
          createdUtc,
          JSON.stringify(post),
          isQuarantined,
          JSON.stringify(scan.findings),
        )

        deleteFts.run(id)
        if (!scan.quarantined && selftext !== "[deleted]" && selftext !== "[removed]") {
          insertFts.run(id, postSubLower, title, selftext)
        } else if (scan.quarantined) {
          quarantinedCount += 1
          flaggedItems.push({
            itemType: "post",
            id,
            subreddit: postSub,
            author: post.author ?? "[deleted]",
            createdUtc,
            permalink: `https://reddit.com${post.permalink ?? `/r/${postSub}/comments/${id}/`}`,
            findings: scan.findings,
            excerpt: `${title} — ${selftext}`.slice(0, 200),
            scannedAt: new Date().toISOString(),
          })
        }
      }
      this.db.exec("COMMIT")
    } catch (error) {
      this.db.exec("ROLLBACK")
      throw error
    }

    this.refreshSyncState(cleanSub, subLower)
    if (flaggedItems.length > 0) {
      this.appendScanReport(flaggedItems)
    }

    return {
      ingested: rawPosts.length,
      quarantined: quarantinedCount,
      newestUtc,
      flaggedItems,
    }
  }

  upsertComments(subreddit: string, rawComments: readonly RedditApiCommentTreeData[]): IngestBatchSummary {
    const cleanSub = normalizeSubreddit(subreddit)
    const subLower = cleanSub.toLowerCase()
    const insertComment = this.db.prepare(`
      INSERT OR REPLACE INTO comments (
        id, link_id, parent_id, subreddit, subreddit_lower, author, author_lower, body, submission_title, permalink, created_utc, raw_json, quarantined, flag_reasons
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    const deleteFts = this.db.prepare("DELETE FROM comments_fts WHERE id = ?")
    const insertFts = this.db.prepare(
      "INSERT INTO comments_fts (id, subreddit_lower, author_lower, body, submission_title) VALUES (?, ?, ?, ?, ?)",
    )

    let newestUtc = 0
    let quarantinedCount = 0
    const flaggedItems: QuarantinedItemRecord[] = []

    this.db.exec("BEGIN TRANSACTION")
    try {
      for (const comment of rawComments) {
        const id = normalizeThingId(comment.id)
        const body = comment.body ?? ""
        const submissionTitle = comment.link_title ?? ""
        const scan = scanContent(`${submissionTitle}\n${body}`)
        const isQuarantined = scan.quarantined ? 1 : 0
        const commentSub = comment.subreddit || cleanSub
        const commentSubLower = commentSub.toLowerCase()
        const author = comment.author ?? "[deleted]"
        const authorLower = author.toLowerCase()
        const createdUtc = Math.trunc(Number(comment.created_utc ?? 0))
        if (createdUtc > newestUtc) newestUtc = createdUtc

        const linkIdRaw = comment.link_id ?? ""
        const linkId = linkIdRaw.startsWith("t3_") ? linkIdRaw : linkIdRaw !== "" ? `t3_${linkIdRaw}` : ""
        const parentId = comment.parent_id ?? linkId

        insertComment.run(
          id,
          linkId,
          parentId,
          commentSub,
          commentSubLower,
          author,
          authorLower,
          body,
          submissionTitle,
          comment.permalink ?? `/r/${commentSub}/comments/${linkId.replace(/^t3_/, "")}/_/${id}/`,
          createdUtc,
          JSON.stringify(comment),
          isQuarantined,
          JSON.stringify(scan.findings),
        )

        deleteFts.run(id)
        if (!scan.quarantined && body !== "[deleted]" && body !== "[removed]" && body.trim() !== "") {
          insertFts.run(id, commentSubLower, authorLower, body, submissionTitle)
        } else if (scan.quarantined) {
          quarantinedCount += 1
          flaggedItems.push({
            itemType: "comment",
            id,
            subreddit: commentSub,
            author,
            createdUtc,
            permalink: `https://reddit.com${comment.permalink ?? `/r/${commentSub}/comments/${linkId.replace(/^t3_/, "")}/_/${id}/`}`,
            findings: scan.findings,
            excerpt: body.slice(0, 200),
            scannedAt: new Date().toISOString(),
          })
        }
      }
      this.db.exec("COMMIT")
    } catch (error) {
      this.db.exec("ROLLBACK")
      throw error
    }

    this.refreshSyncState(cleanSub, subLower)
    if (flaggedItems.length > 0) {
      this.appendScanReport(flaggedItems)
    }

    return {
      ingested: rawComments.length,
      quarantined: quarantinedCount,
      newestUtc,
      flaggedItems,
    }
  }

  private refreshSyncState(subreddit: string, subLower: string): void {
    const postStats = this.db
      .prepare(
        "SELECT COUNT(*) as cnt, COALESCE(MAX(created_utc), 0) as max_utc, COALESCE(SUM(quarantined), 0) as q_cnt FROM posts WHERE subreddit_lower = ?",
      )
      .get(subLower)
    const commentStats = this.db
      .prepare(
        "SELECT COUNT(*) as cnt, COALESCE(MAX(created_utc), 0) as max_utc, COALESCE(SUM(quarantined), 0) as q_cnt FROM comments WHERE subreddit_lower = ?",
      )
      .get(subLower)

    const postCount = Number(postStats?.["cnt"] ?? 0)
    const lastPostUtc = Number(postStats?.["max_utc"] ?? 0)
    const commentCount = Number(commentStats?.["cnt"] ?? 0)
    const lastCommentUtc = Number(commentStats?.["max_utc"] ?? 0)
    const quarantinedCount = Number(postStats?.["q_cnt"] ?? 0) + Number(commentStats?.["q_cnt"] ?? 0)

    this.db
      .prepare(
        `
      INSERT INTO sync_state (
        subreddit_lower, subreddit, last_post_utc, last_comment_utc, post_count, comment_count, quarantined_count, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(subreddit_lower) DO UPDATE SET
        last_post_utc = excluded.last_post_utc,
        last_comment_utc = excluded.last_comment_utc,
        post_count = excluded.post_count,
        comment_count = excluded.comment_count,
        quarantined_count = excluded.quarantined_count,
        updated_at = excluded.updated_at
    `,
      )
      .run(
        subLower,
        subreddit,
        lastPostUtc,
        lastCommentUtc,
        postCount,
        commentCount,
        quarantinedCount,
        new Date().toISOString(),
      )
  }

  private appendScanReport(newItems: readonly QuarantinedItemRecord[]): void {
    mkdirSync(dirname(this.scanReportPath), { recursive: true })
    let existing: QuarantinedItemRecord[] = []
    if (existsSync(this.scanReportPath)) {
      try {
        const parsed = JSON.parse(readFileSync(this.scanReportPath, "utf-8")) as {
          readonly quarantinedItems?: QuarantinedItemRecord[]
        }
        if (Array.isArray(parsed.quarantinedItems)) {
          existing = [...parsed.quarantinedItems]
        }
      } catch {
        existing = []
      }
    }

    const byKey = new Map<string, QuarantinedItemRecord>()
    for (const item of existing) {
      byKey.set(`${item.itemType}:${item.id}`, item)
    }
    for (const item of newItems) {
      byKey.set(`${item.itemType}:${item.id}`, item)
    }

    const allItems = Array.from(byKey.values())
    writeFileSync(
      this.scanReportPath,
      JSON.stringify(
        {
          updatedAt: new Date().toISOString(),
          dbPath: this.dbPath,
          totalQuarantinedItems: allItems.length,
          quarantinedItems: allItems,
        },
        null,
        2,
      ),
      "utf-8",
    )
  }

  listSubredditPosts(subreddit: string, limit: number = 25, beforeUtc?: number): Page<RedditPost> {
    const subLower = normalizeSubreddit(subreddit).toLowerCase()
    const rows =
      beforeUtc !== undefined
        ? this.db
            .prepare(
              "SELECT raw_json FROM posts WHERE subreddit_lower = ? AND quarantined = 0 AND created_utc < ? ORDER BY created_utc DESC LIMIT ?",
            )
            .all(subLower, beforeUtc, limit)
        : this.db
            .prepare(
              "SELECT raw_json FROM posts WHERE subreddit_lower = ? AND quarantined = 0 ORDER BY created_utc DESC LIMIT ?",
            )
            .all(subLower, limit)

    const items = rows.map((r) => parsePostData(JSON.parse(String(r["raw_json"])) as RedditApiPostData))
    const last = items.at(-1)
    const after = items.length >= limit && last !== undefined ? { after: String(last.createdUtc) } : {}
    return {
      items,
      source: "arctic",
      notice: "Served from local SQLite archive.",
      ...after,
    }
  }

  searchPosts(
    query: string,
    options: {
      readonly subreddit?: string
      readonly limit?: number
      readonly beforeUtc?: number
      readonly sinceUtc?: number
    } = {},
  ): Page<RedditPost> {
    const { subreddit, limit = 25, beforeUtc, sinceUtc } = options
    const ftsQuery = toSafeFtsQuery(query)
    const subLower = subreddit !== undefined ? normalizeSubreddit(subreddit).toLowerCase() : undefined

    const conditions: string[] = ["posts_fts MATCH ?", "p.quarantined = 0"]
    const params: SqlParam[] = [ftsQuery]

    if (subLower !== undefined && subLower !== "") {
      conditions.push("p.subreddit_lower = ?")
      params.push(subLower)
    }
    if (beforeUtc !== undefined) {
      conditions.push("p.created_utc < ?")
      params.push(beforeUtc)
    }
    if (sinceUtc !== undefined) {
      conditions.push("p.created_utc >= ?")
      params.push(sinceUtc)
    }
    params.push(limit)

    const sql = `
      SELECT p.raw_json
      FROM posts_fts
      JOIN posts p ON p.id = posts_fts.id
      WHERE ${conditions.join(" AND ")}
      ORDER BY p.created_utc DESC
      LIMIT ?
    `
    const rows = this.db.prepare(sql).all(...params)
    const items = rows.map((r) => parsePostData(JSON.parse(String(r["raw_json"])) as RedditApiPostData))
    const last = items.at(-1)
    const after = items.length >= limit && last !== undefined ? { after: String(last.createdUtc) } : {}
    return {
      items,
      source: "arctic",
      notice: "Served from local SQLite FTS5 archive.",
      ...after,
    }
  }

  searchComments(
    query: string,
    options: {
      readonly subreddit?: string
      readonly author?: string
      readonly limit?: number
      readonly beforeUtc?: number
      readonly sinceUtc?: number
    } = {},
  ): Page<RedditComment> {
    const { subreddit, author, limit = 25, beforeUtc, sinceUtc } = options
    const ftsQuery = toSafeFtsQuery(query)
    const subLower = subreddit !== undefined ? normalizeSubreddit(subreddit).toLowerCase() : undefined
    const authorLower = author !== undefined ? normalizeUsername(author).toLowerCase() : undefined

    const conditions: string[] = ["comments_fts MATCH ?", "c.quarantined = 0"]
    const params: SqlParam[] = [ftsQuery]

    if (subLower !== undefined && subLower !== "") {
      conditions.push("c.subreddit_lower = ?")
      params.push(subLower)
    }
    if (authorLower !== undefined && authorLower !== "") {
      conditions.push("c.author_lower = ?")
      params.push(authorLower)
    }
    if (beforeUtc !== undefined) {
      conditions.push("c.created_utc < ?")
      params.push(beforeUtc)
    }
    if (sinceUtc !== undefined) {
      conditions.push("c.created_utc >= ?")
      params.push(sinceUtc)
    }
    params.push(limit)

    const sql = `
      SELECT c.raw_json, c.submission_title
      FROM comments_fts
      JOIN comments c ON c.id = comments_fts.id
      WHERE ${conditions.join(" AND ")}
      ORDER BY c.created_utc DESC
      LIMIT ?
    `
    const rows = this.db.prepare(sql).all(...params)
    const items = rows.map((r) => {
      const raw = JSON.parse(String(r["raw_json"])) as RedditApiCommentTreeData
      const title = String(r["submission_title"] ?? "")
      return parseCommentData(raw, title !== "" ? title : undefined)
    })
    const last = items.at(-1)
    const after = items.length >= limit && last !== undefined ? { after: String(last.createdUtc) } : {}
    return {
      items,
      source: "arctic",
      notice: "Served from local SQLite FTS5 archive.",
      ...after,
    }
  }

  getPost(postId: string): RedditPost | undefined {
    const id = normalizeThingId(postId)
    const row = this.db.prepare("SELECT raw_json FROM posts WHERE id = ? AND quarantined = 0").get(id)
    if (row === undefined) return undefined
    return parsePostData(JSON.parse(String(row["raw_json"])) as RedditApiPostData)
  }

  getPostComments(postId: string, limit: number = 100): PostComments | undefined {
    const post = this.getPost(postId)
    if (post === undefined) return undefined

    const linkId = `t3_${post.id}`
    const rows = this.db
      .prepare("SELECT raw_json FROM comments WHERE link_id = ? AND quarantined = 0 ORDER BY created_utc ASC LIMIT ?")
      .all(linkId, limit)

    if (rows.length === 0) return undefined

    const rawComments = rows.map((r) => JSON.parse(String(r["raw_json"])) as RedditApiCommentTreeData)
    const byParent = new Map<string, RedditApiCommentTreeData[]>()
    for (const c of rawComments) {
      const parent = c.parent_id ?? linkId
      const existing = byParent.get(parent) ?? []
      existing.push(c)
      byParent.set(parent, existing)
    }

    const flattened: RedditComment[] = []
    const visit = (parentId: string, depth: number): void => {
      const children = byParent.get(parentId) ?? []
      for (const child of children) {
        flattened.push(parseCommentData(child, post.title, depth))
        visit(`t1_${child.id}`, depth + 1)
      }
    }
    visit(linkId, 0)

    // Include any orphan comments whose parent comment wasn't in the slice
    const visitedIds = new Set(flattened.map((c) => c.id))
    for (const c of rawComments) {
      if (!visitedIds.has(c.id)) {
        flattened.push(parseCommentData(c, post.title, 0))
      }
    }

    return {
      post,
      comments: flattened,
      moreIds: [],
    }
  }

  rescanAll(): {
    readonly scannedPosts: number
    readonly scannedComments: number
    readonly quarantinedPosts: number
    readonly quarantinedComments: number
    readonly reportPath: string
  } {
    const allFlagged: QuarantinedItemRecord[] = []
    let quarantinedPosts = 0
    let quarantinedComments = 0

    const posts = this.db
      .prepare("SELECT id, subreddit, author, title, selftext, url, permalink, created_utc FROM posts")
      .all()
    const updatePost = this.db.prepare("UPDATE posts SET quarantined = ?, flag_reasons = ? WHERE id = ?")
    const deletePostFts = this.db.prepare("DELETE FROM posts_fts WHERE id = ?")

    for (const p of posts) {
      const id = String(p["id"])
      const title = String(p["title"] ?? "")
      const selftext = String(p["selftext"] ?? "")
      const url = String(p["url"] ?? "")
      const scan = scanContent(`${title}\n${selftext}\n${url}`)
      if (scan.quarantined) {
        quarantinedPosts += 1
        updatePost.run(1, JSON.stringify(scan.findings), id)
        deletePostFts.run(id)
        allFlagged.push({
          itemType: "post",
          id,
          subreddit: String(p["subreddit"]),
          author: String(p["author"]),
          createdUtc: Number(p["created_utc"]),
          permalink: `https://reddit.com${String(p["permalink"])}`,
          findings: scan.findings,
          excerpt: `${title} — ${selftext}`.slice(0, 200),
          scannedAt: new Date().toISOString(),
        })
      } else {
        updatePost.run(0, "[]", id)
      }
    }

    const comments = this.db
      .prepare("SELECT id, subreddit, author, body, submission_title, permalink, created_utc FROM comments")
      .all()
    const updateComment = this.db.prepare("UPDATE comments SET quarantined = ?, flag_reasons = ? WHERE id = ?")
    const deleteCommentFts = this.db.prepare("DELETE FROM comments_fts WHERE id = ?")

    for (const c of comments) {
      const id = String(c["id"])
      const body = String(c["body"] ?? "")
      const submissionTitle = String(c["submission_title"] ?? "")
      const scan = scanContent(`${submissionTitle}\n${body}`)
      if (scan.quarantined) {
        quarantinedComments += 1
        updateComment.run(1, JSON.stringify(scan.findings), id)
        deleteCommentFts.run(id)
        allFlagged.push({
          itemType: "comment",
          id,
          subreddit: String(c["subreddit"]),
          author: String(c["author"]),
          createdUtc: Number(c["created_utc"]),
          permalink: `https://reddit.com${String(c["permalink"])}`,
          findings: scan.findings,
          excerpt: body.slice(0, 200),
          scannedAt: new Date().toISOString(),
        })
      } else {
        updateComment.run(0, "[]", id)
      }
    }

    // Write fresh scan report
    mkdirSync(dirname(this.scanReportPath), { recursive: true })
    writeFileSync(
      this.scanReportPath,
      JSON.stringify(
        {
          updatedAt: new Date().toISOString(),
          dbPath: this.dbPath,
          scannedPosts: posts.length,
          scannedComments: comments.length,
          totalQuarantinedItems: allFlagged.length,
          quarantinedItems: allFlagged,
        },
        null,
        2,
      ),
      "utf-8",
    )

    const subs = this.db.prepare("SELECT subreddit, subreddit_lower FROM sync_state").all()
    for (const s of subs) {
      this.refreshSyncState(String(s["subreddit"]), String(s["subreddit_lower"]))
    }

    return {
      scannedPosts: posts.length,
      scannedComments: comments.length,
      quarantinedPosts,
      quarantinedComments,
      reportPath: this.scanReportPath,
    }
  }

  getStatus(): ArchiveStatusSummary {
    const rows = this.db.prepare("SELECT * FROM sync_state ORDER BY post_count + comment_count DESC").all()
    const subreddits: SubredditSyncStats[] = rows.map((row) => ({
      subreddit: String(row["subreddit"]),
      lastPostUtc: Number(row["last_post_utc"]),
      lastCommentUtc: Number(row["last_comment_utc"]),
      postCount: Number(row["post_count"]),
      commentCount: Number(row["comment_count"]),
      quarantinedCount: Number(row["quarantined_count"]),
      updatedAt: String(row["updated_at"]),
    }))

    return {
      dbPath: this.dbPath,
      scanReportPath: this.scanReportPath,
      runtime: this.runtime,
      subreddits,
      totalPosts: subreddits.reduce((acc, s) => acc + s.postCount, 0),
      totalComments: subreddits.reduce((acc, s) => acc + s.commentCount, 0),
      totalQuarantined: subreddits.reduce((acc, s) => acc + s.quarantinedCount, 0),
    }
  }

  close(): void {
    this.db.close()
  }
}
