import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../util/logger.js", () => ({
  logger: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));
vi.mock("./accounts.js", () => ({
  listIndexedWeixinAccountIds: () => [],
  loadWeixinAccount: () => undefined,
  loadConfigAcctwebBaseUrl: () => undefined,
}));
vi.mock("qrcode-terminal", () => ({ default: { generate: vi.fn() } }));

const fetchImpl = vi.fn();

import { startWeixinLoginWithQr, statusNeedsVerifyCode } from "./login-qr.js";

const TICKET = "0a1b2c3d4e5f60718293a4b5c6d7e8f9";
const TICKET_2 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
  } as Response;
}

function ticketBody(ticket: string) {
  return {
    bot_spam_ticket: ticket,
    auth_url: "liteapp://auth",
    expire_time: 1_800_000_000,
  };
}

function qrBody(id: string) {
  return {
    qrcode: id,
    qrcode_img_content: `https://ilinkai.weixin.qq.com/ilink/q/${id}`,
  };
}

beforeEach(() => {
  fetchImpl.mockReset();
});

describe("startWeixinLoginWithQr", () => {
  it("self mode fetches a ticket and posts it with the bind qr request", async () => {
    fetchImpl
      .mockResolvedValueOnce(jsonResponse(ticketBody(TICKET)))
      .mockResolvedValueOnce(jsonResponse(qrBody("qr-1")));
    const readLine = vi.fn(async () => "");
    const result = await startWeixinLoginWithQr({
      apiBaseUrl: "https://ilinkai.weixin.qq.com",
      accountId: "self-case",
      io: {
        readLine,
        fetchImpl,
        nowMs: () => 1_700_000_000_000,
        sleep: async () => {},
        write: () => {},
      },
    });
    expect(result.qrcodeUrl).toBe("https://ilinkai.weixin.qq.com/ilink/q/qr-1");
    expect(result.bindOwnerMode).toBe("self");
    expect(result.message).toContain("让连接此 OpenClaw 的用户用手机微信扫描以下二维码");
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(String(fetchImpl.mock.calls[0][0])).toContain("step=get_auth_url");
    const post = fetchImpl.mock.calls[1][1] as RequestInit;
    expect(String(fetchImpl.mock.calls[1][0])).toContain("get_bot_qrcode");
    expect(JSON.parse(String(post.body))).toEqual({
      local_token_list: [],
      bot_spam_ticket: TICKET,
    });
    expect(fetchImpl.mock.calls.map((call) => String(call[0])).join("\n")).not.toContain(
      "query_auth_result",
    );
  });

  it("other mode waits for auth_status 1 before posting the bind qr", async () => {
    fetchImpl
      .mockResolvedValueOnce(jsonResponse(ticketBody(TICKET)))
      .mockResolvedValueOnce(jsonResponse({ auth_status: 0 }))
      .mockResolvedValueOnce(jsonResponse({ auth_status: 1 }))
      .mockResolvedValueOnce(jsonResponse(qrBody("qr-2")));
    const write = vi.fn();
    const result = await startWeixinLoginWithQr({
      apiBaseUrl: "https://ilinkai.weixin.qq.com",
      accountId: "other-case",
      io: {
        readLine: async () => "n",
        write,
        fetchImpl,
        nowMs: () => 1_700_000_000_000,
        sleep: async () => {},
      },
    });
    expect(result.bindOwnerMode).toBe("other");
    expect(write.mock.calls.map((c) => String(c[0])).join("")).toContain("实名信息授权");
    expect(String(fetchImpl.mock.calls[2][0])).toContain("query_auth_result");
    expect(
      JSON.parse(String((fetchImpl.mock.calls[3][1] as RequestInit).body)).bot_spam_ticket,
    ).toBe(TICKET);
  });

  it("does not request a bind qr when realname auth fails", async () => {
    fetchImpl
      .mockResolvedValueOnce(jsonResponse(ticketBody(TICKET)))
      .mockResolvedValueOnce(jsonResponse({ auth_status: 2 }));
    const result = await startWeixinLoginWithQr({
      apiBaseUrl: "https://ilinkai.weixin.qq.com",
      accountId: "fail-case",
      io: {
        readLine: async () => "n",
        write: () => {},
        fetchImpl,
        nowMs: () => 1_700_000_000_000,
        sleep: async () => {},
      },
    });
    expect(result.qrcodeUrl).toBeUndefined();
    expect(result.message).toBe("实名授权未通过，无法连接。");
    expect(fetchImpl.mock.calls.map((c) => String(c[0])).join("\n")).not.toContain(
      "get_bot_qrcode",
    );
  });

  it("does not request a bind qr when get_auth_url fails", async () => {
    fetchImpl.mockResolvedValueOnce(jsonResponse({ errmsg: "no" }, 500));
    const result = await startWeixinLoginWithQr({
      apiBaseUrl: "https://ilinkai.weixin.qq.com",
      accountId: "http-fail",
      io: { readLine: async () => "", fetchImpl, nowMs: () => 1_700_000_000_000, write: () => {} },
    });
    expect(result.qrcodeUrl).toBeUndefined();
    expect(result.message).toBe("无法获取绑定凭证，连接已停止。");
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it("restarts the whole flow on every call for the same account", async () => {
    fetchImpl
      .mockResolvedValueOnce(jsonResponse(ticketBody(TICKET)))
      .mockResolvedValueOnce(jsonResponse(qrBody("qr-1")))
      .mockResolvedValueOnce(jsonResponse(ticketBody(TICKET_2)))
      .mockResolvedValueOnce(jsonResponse(qrBody("qr-2")));
    const readLine = vi.fn(async () => "");
    const io = {
      readLine,
      fetchImpl,
      nowMs: () => 1_700_000_000_000,
      sleep: async () => {},
      write: () => {},
    };
    const first = await startWeixinLoginWithQr({
      apiBaseUrl: "https://ilinkai.weixin.qq.com",
      accountId: "restart-case",
      io,
    });
    const second = await startWeixinLoginWithQr({
      apiBaseUrl: "https://ilinkai.weixin.qq.com",
      accountId: "restart-case",
      force: true,
      io,
    });
    expect(readLine).toHaveBeenCalledTimes(2);
    expect(
      fetchImpl.mock.calls.filter((call) => String(call[0]).includes("get_auth_url")),
    ).toHaveLength(2);
    expect(first.qrcodeUrl).toBe("https://ilinkai.weixin.qq.com/ilink/q/qr-1");
    expect(second.qrcodeUrl).toBe("https://ilinkai.weixin.qq.com/ilink/q/qr-2");
    expect(
      JSON.parse(String((fetchImpl.mock.calls[3][1] as RequestInit).body)).bot_spam_ticket,
    ).toBe(TICKET_2);
  });
});

describe("statusNeedsVerifyCode", () => {
  it("treats every status containing need_verifycode as a pin prompt", () => {
    expect(statusNeedsVerifyCode("need_verifycode")).toBe(true);
    expect(statusNeedsVerifyCode("confirmed_but_need_verifycode")).toBe(true);
    expect(statusNeedsVerifyCode("verify_code_blocked")).toBe(false);
    expect(statusNeedsVerifyCode("confirmed")).toBe(false);
  });
});
