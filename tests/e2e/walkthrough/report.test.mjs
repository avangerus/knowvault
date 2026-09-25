// Card U-1 proof for the report rule: a step whose request answers 5xx is
// reported failed and names the request path. The test runs the real recorder
// against a deliberately broken endpoint served by a local HTTP server, so the
// assertion covers the actual response/console observation path, not a
// hand-built step object.

import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import test from "node:test";

import { chromium } from "playwright";

import { stepFailed, Walkthrough } from "./report.mjs";

async function brokenServer() {
  const server = http.createServer((request, response) => {
    if ((request.url ?? "").startsWith("/api/v1/broken")) {
      response.writeHead(500, { "content-type": "text/plain" });
      response.end("deliberately broken endpoint\n");
      return;
    }
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end("<!doctype html><title>stand</title><p>ok</p>");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { server, baseURL: `http://127.0.0.1:${server.address().port}` };
}

test("a step whose request answers 5xx is failed with its request path", async () => {
  const { server, baseURL } = await brokenServer();
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage();
    const walk = new Walkthrough(page);
    const step = await walk.step("broken endpoint", async () => {
      const response = await page.goto(`${baseURL}/api/v1/broken?probe=1`);
      assert.equal(response.status(), 500);
    });
    assert.equal(step.status, "failed");
    assert.equal(stepFailed(step), true);
    assert.ok(
      step.httpErrors.some((error) => error.status === 500 && error.path === "/api/v1/broken?probe=1"),
      `5xx with the request path was not reported: ${JSON.stringify(step.httpErrors)}`,
    );
  } finally {
    await browser.close();
    server.close();
  }
});

test("a step with no 5xx and no console error passes", async () => {
  const { server, baseURL } = await brokenServer();
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage();
    const walk = new Walkthrough(page);
    const step = await walk.step("healthy endpoint", async () => {
      const response = await page.goto(`${baseURL}/`);
      assert.equal(response.status(), 200);
    });
    assert.equal(step.status, "passed");
    assert.deepEqual(step.httpErrors, []);
    assert.deepEqual(step.consoleErrors, []);
  } finally {
    await browser.close();
    server.close();
  }
});
