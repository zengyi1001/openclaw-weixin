import { loadConfigAcctwebBaseUrl } from "./accounts.js";
import { logger } from "../util/logger.js";
import { redactBody, redactToken, redactUrl } from "../util/redact.js";

export const ACCTWEB_ORIGIN = "https://weixin110.qq.com";
export const ACCTWEB_CGI_PATH = "/security/acct/botrealnameverifycgi";
export const REALNAME_AUTH_WAIT_MS = 480_000;
const ACCTWEB_TIMEOUT_MS = 10_000;
const TICKET_RE = /^[0-9a-fA-F]{32}$/;

export type BotSpamAuthStatus = 0 | 1 | 2 | 3;

export type BotSpamTicketContext = {
  botSpamTicket: string;
  authUrl: string;
  expireTimeSec: number;
};

export class BotSpamTicketError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BotSpamTicketError";
  }
}

const FETCH_TICKET_FAILED = "无法获取绑定凭证，连接已停止。";
const TICKET_INVALID = "绑定凭证无效，请重新开始连接。";
const INVALID_ACCTWEB_BASE_URL = "绑定接口地址配置无效，连接已停止。";
const PENDING_LOG_INTERVAL_MS = 30_000;

function acctwebStep(url: string): string {
  try {
    return new URL(url).searchParams.get("step") ?? "unknown";
  } catch {
    return "unknown";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export function parseBotSpamTicketContext(raw: unknown, nowSec: number): BotSpamTicketContext {
  if (!isRecord(raw)) {
    throw new BotSpamTicketError(FETCH_TICKET_FAILED);
  }
  if (typeof raw.ret === "number" && raw.ret !== 0) {
    logger.warn(`get_auth_url rejected ret=${raw.ret}`);
    throw new BotSpamTicketError(FETCH_TICKET_FAILED);
  }
  if (typeof raw.errcode === "number" && raw.errcode !== 0) {
    logger.warn(`get_auth_url rejected errcode=${raw.errcode}`);
    throw new BotSpamTicketError(FETCH_TICKET_FAILED);
  }
  const ticket = raw.bot_spam_ticket;
  const authUrl = raw.auth_url;
  const expireTimeSec = raw.expire_time;
  if (typeof ticket !== "string" || !TICKET_RE.test(ticket)) {
    logger.warn("get_auth_url bot_spam_ticket missing or not 32 hex");
    throw new BotSpamTicketError(FETCH_TICKET_FAILED);
  }
  if (typeof authUrl !== "string" || authUrl.length === 0) {
    logger.warn("get_auth_url auth_url empty");
    throw new BotSpamTicketError(FETCH_TICKET_FAILED);
  }
  if (
    typeof expireTimeSec !== "number" ||
    !Number.isFinite(expireTimeSec) ||
    expireTimeSec <= nowSec
  ) {
    logger.warn(
      `get_auth_url expire_time invalid or expired expire_time=${String(expireTimeSec)} nowSec=${nowSec}`,
    );
    throw new BotSpamTicketError(FETCH_TICKET_FAILED);
  }
  return { botSpamTicket: ticket, authUrl, expireTimeSec };
}

export function parseBotSpamAuthStatus(raw: unknown): BotSpamAuthStatus {
  if (!isRecord(raw) || typeof raw.auth_status !== "number") {
    logger.warn("query_auth_result auth_status missing");
    throw new BotSpamTicketError(FETCH_TICKET_FAILED);
  }
  const status = raw.auth_status;
  if (status !== 0 && status !== 1 && status !== 2 && status !== 3) {
    logger.warn(`query_auth_result auth_status invalid status=${String(status)}`);
    throw new BotSpamTicketError(FETCH_TICKET_FAILED);
  }
  return status;
}

/** Use scheme, host, and port from `acctwebBaseUrl`. An empty value keeps the public 443 origin. */
export function resolveAcctwebOrigin(raw: string | undefined): string {
  const value = raw?.trim();
  if (!value) return ACCTWEB_ORIGIN;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    logger.warn("acctwebBaseUrl is not a URL");
    throw new BotSpamTicketError(INVALID_ACCTWEB_BASE_URL);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    logger.warn(`acctwebBaseUrl scheme rejected scheme=${parsed.protocol}`);
    throw new BotSpamTicketError(INVALID_ACCTWEB_BASE_URL);
  }
  if (!parsed.hostname) {
    logger.warn("acctwebBaseUrl missing host");
    throw new BotSpamTicketError(INVALID_ACCTWEB_BASE_URL);
  }
  if (parsed.pathname !== "/" && parsed.pathname !== "") {
    logger.info(`acctwebBaseUrl path ignored origin=${parsed.origin}`);
  }
  return parsed.origin;
}

function requestAcctwebOrigin(opts: { acctwebOrigin?: string; accountId?: string }): string {
  if (opts.acctwebOrigin !== undefined) return resolveAcctwebOrigin(opts.acctwebOrigin);
  return resolveAcctwebOrigin(loadConfigAcctwebBaseUrl(opts.accountId));
}

function acctwebUrl(step: string, params: Record<string, string>, origin: string): string {
  const url = new URL(ACCTWEB_CGI_PATH, origin);
  url.searchParams.set("step", step);
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value);
  }
  return url.toString();
}

async function acctwebGet(opts: {
  url: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}): Promise<unknown> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const step = acctwebStep(opts.url);
  logger.info(`acctweb ${step} GET ${redactUrl(opts.url)}`);
  let response: Response;
  try {
    response = await fetchImpl(opts.url, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(opts.timeoutMs ?? ACCTWEB_TIMEOUT_MS),
    });
  } catch (err) {
    if (err instanceof BotSpamTicketError) throw err;
    logger.warn(`acctweb ${step} request failed: ${String(err)}`);
    throw new BotSpamTicketError(FETCH_TICKET_FAILED);
  }
  const rawText = await response.text();
  if (!response.ok) {
    logger.warn(`acctweb ${step} HTTP ${response.status} body=${redactBody(rawText)}`);
    throw new BotSpamTicketError(FETCH_TICKET_FAILED);
  }
  try {
    return JSON.parse(rawText) as unknown;
  } catch (err) {
    if (err instanceof BotSpamTicketError) throw err;
    logger.warn(`acctweb ${step} response is not JSON body=${redactBody(rawText)}`);
    throw new BotSpamTicketError(FETCH_TICKET_FAILED);
  }
}

export async function fetchBotSpamTicket(opts: {
  pluginVersion: string;
  fetchImpl?: typeof fetch;
  nowSec?: number;
  timeoutMs?: number;
  accountId?: string;
  acctwebOrigin?: string;
}): Promise<BotSpamTicketContext> {
  const nowSec = opts.nowSec ?? Math.floor(Date.now() / 1000);
  const origin = requestAcctwebOrigin(opts);
  logger.info(`get_auth_url plugin_version=${opts.pluginVersion} origin=${origin}`);
  const raw = await acctwebGet({
    url: acctwebUrl("get_auth_url", { plugin_version: opts.pluginVersion }, origin),
    fetchImpl: opts.fetchImpl,
    timeoutMs: opts.timeoutMs,
  });
  const ticket = parseBotSpamTicketContext(raw, nowSec);
  logger.info(
    `get_auth_url ok ticket=${redactToken(ticket.botSpamTicket)} expire_time=${ticket.expireTimeSec} auth_url=${redactUrl(ticket.authUrl)}`,
  );
  return ticket;
}

export async function queryBotSpamAuthResult(opts: {
  botSpamTicket: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  accountId?: string;
  acctwebOrigin?: string;
}): Promise<BotSpamAuthStatus> {
  const origin = requestAcctwebOrigin(opts);
  const raw = await acctwebGet({
    url: acctwebUrl("query_auth_result", { bot_spam_ticket: opts.botSpamTicket }, origin),
    fetchImpl: opts.fetchImpl,
    timeoutMs: opts.timeoutMs,
  });
  return parseBotSpamAuthStatus(raw);
}

export async function waitForBotSpamAuth(opts: {
  ticket: BotSpamTicketContext;
  pollIntervalMs?: number;
  deadlineMs?: number;
  nowMs?: () => number;
  sleep?: (ms: number) => Promise<void>;
  query?: (ticket: string) => Promise<BotSpamAuthStatus>;
  refreshTicket?: () => Promise<BotSpamTicketContext>;
  onTicketReplaced?: (ticket: BotSpamTicketContext) => Promise<void> | void;
}): Promise<BotSpamTicketContext> {
  const nowMs = opts.nowMs ?? (() => Date.now());
  const sleep = opts.sleep ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));
  const pollIntervalMs = opts.pollIntervalMs ?? 1000;
  let ticket = opts.ticket;
  let deadlineMs =
    opts.deadlineMs ?? Math.min(nowMs() + REALNAME_AUTH_WAIT_MS, ticket.expireTimeSec * 1000);
  let refreshedInvalidTicket = false;
  let lastLoggedStatus: BotSpamAuthStatus | undefined;
  let lastPendingLogMs = 0;
  let lastQueryErrorLogMs = 0;
  logger.info(
    `query_auth_result start ticket=${redactToken(ticket.botSpamTicket)} deadlineMs=${deadlineMs} expire_time=${ticket.expireTimeSec}`,
  );

  for (;;) {
    const now = nowMs();
    if (now >= deadlineMs || now >= ticket.expireTimeSec * 1000) {
      logger.warn(
        `query_auth_result timed out ticket=${redactToken(ticket.botSpamTicket)} nowMs=${now} deadlineMs=${deadlineMs} expire_time=${ticket.expireTimeSec}`,
      );
      throw new BotSpamTicketError("实名授权超时，请重新开始连接。");
    }
    let status: BotSpamAuthStatus = 0;
    try {
      status = opts.query ? await opts.query(ticket.botSpamTicket) : 0;
    } catch (err) {
      if (lastQueryErrorLogMs === 0 || now - lastQueryErrorLogMs >= PENDING_LOG_INTERVAL_MS) {
        logger.warn(
          `query_auth_result failed, treat as pending ticket=${redactToken(ticket.botSpamTicket)} error=${String(err)}`,
        );
        lastQueryErrorLogMs = now;
      }
      status = 0;
    }
    if (
      status !== lastLoggedStatus ||
      (status === 0 && now - lastPendingLogMs >= PENDING_LOG_INTERVAL_MS)
    ) {
      logger.info(
        `query_auth_result auth_status=${status} ticket=${redactToken(ticket.botSpamTicket)}`,
      );
      lastLoggedStatus = status;
      if (status === 0) lastPendingLogMs = now;
    }
    if (status === 1) {
      logger.info(`query_auth_result passed ticket=${redactToken(ticket.botSpamTicket)}`);
      return ticket;
    }
    if (status === 2) {
      logger.warn(`query_auth_result rejected ticket=${redactToken(ticket.botSpamTicket)}`);
      throw new BotSpamTicketError("实名授权未通过，无法连接。");
    }
    if (status === 3) {
      if (refreshedInvalidTicket || !opts.refreshTicket) {
        logger.warn(
          `query_auth_result ticket still invalid ticket=${redactToken(ticket.botSpamTicket)}`,
        );
        throw new BotSpamTicketError(TICKET_INVALID);
      }
      refreshedInvalidTicket = true;
      logger.warn(
        `query_auth_result auth_status=3, refreshing ticket previous=${redactToken(ticket.botSpamTicket)}`,
      );
      try {
        ticket = await opts.refreshTicket();
        logger.info(
          `query_auth_result ticket replaced ticket=${redactToken(ticket.botSpamTicket)} expire_time=${ticket.expireTimeSec}`,
        );
        await opts.onTicketReplaced?.(ticket);
        deadlineMs = Math.min(deadlineMs, ticket.expireTimeSec * 1000);
        lastLoggedStatus = undefined;
      } catch (err) {
        logger.warn(`query_auth_result ticket refresh failed: ${String(err)}`);
        if (err instanceof BotSpamTicketError && err.message === TICKET_INVALID) {
          throw err;
        }
        throw new BotSpamTicketError(TICKET_INVALID);
      }
      continue;
    }
    await sleep(pollIntervalMs);
  }
}
