import { afterEach, describe, expect, it, vi } from "vitest";

import {
  BotSpamTicketError,
  fetchBotSpamTicket,
  queryBotSpamAuthResult,
  resolveAcctwebOrigin,
  waitForBotSpamAuth,
} from "./bot-spam-ticket.js";

const TICKET = "0a1b2c3d4e5f60718293a4b5c6d7e8f9";
const AUTH_URL = `liteapp://wxalite41747693cb27020d46b1ee0c8c29e3f3/pages/realname-verify/entry?bot_spam_ticket=${TICKET}`;

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(JSON.stringify(body)),
  } as Response;
}

describe("resolveAcctwebOrigin", () => {
  it("keeps the public 443 origin when unset", () => {
    expect(resolveAcctwebOrigin(undefined)).toBe("https://weixin110.qq.com");
    expect(resolveAcctwebOrigin("  ")).toBe("https://weixin110.qq.com");
  });

  it("uses the configured host and port and drops any CGI path", () => {
    expect(resolveAcctwebOrigin("http://10.1.2.3:8088")).toBe("http://10.1.2.3:8088");
    expect(resolveAcctwebOrigin("http://10.1.2.3:8088/security/acct/botrealnameverifycgi")).toBe(
      "http://10.1.2.3:8088",
    );
  });

  it("rejects a non-http origin", () => {
    expect(() => resolveAcctwebOrigin("ftp://10.1.2.3:8088")).toThrow(
      "绑定接口地址配置无效，连接已停止。",
    );
  });
});

describe("fetchBotSpamTicket", () => {
  afterEach(() => vi.restoreAllMocks());

  it("returns the server ticket unchanged", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({
        bot_spam_ticket: TICKET,
        auth_url: AUTH_URL,
        expire_time: 1_800_000_000,
      }),
    );
    const got = await fetchBotSpamTicket({
      pluginVersion: "2.4.10",
      fetchImpl,
      nowSec: 1_700_000_000,
    });
    expect(got).toEqual({
      botSpamTicket: TICKET,
      authUrl: AUTH_URL,
      expireTimeSec: 1_800_000_000,
    });
    const url = String(fetchImpl.mock.calls[0][0]);
    expect(url).toContain("https://weixin110.qq.com/security/acct/botrealnameverifycgi");
    expect(url).toContain("step=get_auth_url");
    expect(url).toContain("plugin_version=2.4.10");
    expect(fetchImpl.mock.calls[0][1]).toMatchObject({
      method: "GET",
      headers: { Accept: "application/json" },
    });
  });

  it("calls the office-network origin on port 8088 when configured", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({
        bot_spam_ticket: TICKET,
        auth_url: AUTH_URL,
        expire_time: 1_800_000_000,
      }),
    );
    await fetchBotSpamTicket({
      pluginVersion: "3.0.0-dev-001",
      fetchImpl,
      nowSec: 1_700_000_000,
      acctwebOrigin: "http://10.1.2.3:8088",
    });
    const url = new URL(String(fetchImpl.mock.calls[0][0]));
    expect(url.origin).toBe("http://10.1.2.3:8088");
    expect(url.pathname).toBe("/security/acct/botrealnameverifycgi");
    expect(url.searchParams.get("step")).toBe("get_auth_url");
  });

  it("rejects a non-zero ret even if a ticket is present", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({
        ret: 1,
        bot_spam_ticket: TICKET,
        auth_url: AUTH_URL,
        expire_time: 1_800_000_000,
      }),
    );
    await expect(
      fetchBotSpamTicket({
        pluginVersion: "2.4.10",
        fetchImpl,
        nowSec: 1_700_000_000,
      }),
    ).rejects.toBeInstanceOf(BotSpamTicketError);
  });

  it("rejects an expired ticket", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({
        bot_spam_ticket: TICKET,
        auth_url: AUTH_URL,
        expire_time: 1_600_000_000,
      }),
    );
    await expect(
      fetchBotSpamTicket({
        pluginVersion: "2.4.10",
        fetchImpl,
        nowSec: 1_700_000_000,
      }),
    ).rejects.toBeInstanceOf(BotSpamTicketError);
  });
});

describe("waitForBotSpamAuth", () => {
  it("keeps polling while pending and returns on pass", async () => {
    const query = vi.fn().mockResolvedValueOnce(0).mockResolvedValueOnce(1);
    const sleep = vi.fn(async () => {});
    const got = await waitForBotSpamAuth({
      ticket: { botSpamTicket: TICKET, authUrl: AUTH_URL, expireTimeSec: 1_800_000_000 },
      nowMs: () => 1_700_000_000_000,
      sleep,
      query,
      deadlineMs: 1_700_000_600_000,
    });
    expect(got.botSpamTicket).toBe(TICKET);
    expect(query).toHaveBeenCalledTimes(2);
    expect(sleep).toHaveBeenCalledWith(1000);
  });

  it("stops on auth failure without refreshing", async () => {
    const refreshTicket = vi.fn();
    await expect(
      waitForBotSpamAuth({
        ticket: { botSpamTicket: TICKET, authUrl: AUTH_URL, expireTimeSec: 1_800_000_000 },
        nowMs: () => 1_700_000_000_000,
        sleep: async () => {},
        query: async () => 2,
        refreshTicket,
        deadlineMs: 1_700_000_600_000,
      }),
    ).rejects.toThrow("实名授权未通过，无法连接。");
    expect(refreshTicket).not.toHaveBeenCalled();
  });

  it("refreshes once on invalid ticket and then fails", async () => {
    const next = {
      botSpamTicket: "aabbccddeeff00112233445566778899",
      authUrl: AUTH_URL,
      expireTimeSec: 1_800_000_100,
    };
    const query = vi.fn().mockResolvedValue(3);
    const refreshTicket = vi.fn(async () => next);
    const onTicketReplaced = vi.fn(async () => {});
    await expect(
      waitForBotSpamAuth({
        ticket: { botSpamTicket: TICKET, authUrl: AUTH_URL, expireTimeSec: 1_800_000_000 },
        nowMs: () => 1_700_000_000_000,
        sleep: async () => {},
        query,
        refreshTicket,
        onTicketReplaced,
        deadlineMs: 1_700_000_600_000,
      }),
    ).rejects.toThrow("绑定凭证无效，请重新开始连接。");
    expect(refreshTicket).toHaveBeenCalledOnce();
    expect(onTicketReplaced).toHaveBeenCalledWith(next);
  });
});

describe("queryBotSpamAuthResult", () => {
  it("reads auth_status", async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ auth_status: 1 }));
    await expect(queryBotSpamAuthResult({ botSpamTicket: TICKET, fetchImpl })).resolves.toBe(1);
    expect(String(fetchImpl.mock.calls[0][0])).toContain(`bot_spam_ticket=${TICKET}`);
    expect(String(fetchImpl.mock.calls[0][0])).toContain("step=query_auth_result");
  });
});
