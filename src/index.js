import { AwsClient } from "aws4fetch";
import { verifyGoogleIdToken } from "./google.js";

function timingSafeEqual(a, b) {
  const encoder = new TextEncoder();
  const aBytes = encoder.encode(a);
  const bBytes = encoder.encode(b);
  if (aBytes.length !== bBytes.length) return false;
  let diff = 0;
  for (let i = 0; i < aBytes.length; i++) {
    diff |= aBytes[i] ^ bBytes[i];
  }
  return diff === 0;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function ec2Request(aws, region, action, instanceId) {
  const endpoint = `https://ec2.${region}.amazonaws.com/?Action=${action}&InstanceId.1=${instanceId}&Version=2016-11-15`;
  const res = await aws.fetch(endpoint);
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${action} failed: ${body}`);
  }
  return res.text();
}

async function describeInstance(aws, region, instanceId) {
  const xml = await ec2Request(aws, region, "DescribeInstances", instanceId);
  const stateMatch = xml.match(/<instanceState>[\s\S]*?<name>([^<]+)<\/name>/);
  const ipMatch = xml.match(/<ipAddress>([^<]+)<\/ipAddress>/);
  return {
    state: stateMatch ? stateMatch[1] : null,
    ip: ipMatch ? ipMatch[1] : null,
  };
}

// Accepts either a Google ID token (Authorization: Bearer ...) or the legacy shared X-Auth-Token.
async function isAuthorized(request, env) {
  const bearer = (request.headers.get("Authorization") ?? "").match(/^Bearer\s+(.+)$/i);
  if (bearer) {
    try {
      await verifyGoogleIdToken(bearer[1], env);
      return true;
    } catch {
      return false;
    }
  }
  const token = request.headers.get("X-Auth-Token") ?? "";
  return Boolean(env.AUTH_TOKEN) && timingSafeEqual(token, env.AUTH_TOKEN);
}

const POLL_INTERVAL_MS = 5000;
const POLL_TIMEOUT_MS = 120000;

export default {
  async fetch(request, env) {
    if (!(await isAuthorized(request, env))) {
      return new Response(JSON.stringify({ error: "unauthorized" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      });
    }

    const aws = new AwsClient({
      accessKeyId: env.AWS_ACCESS_KEY_ID,
      secretAccessKey: env.AWS_SECRET_ACCESS_KEY,
      region: env.AWS_REGION,
      service: "ec2",
    });

    const action = new URL(request.url).searchParams.get("action");

    if (action === "status") {
      try {
        const { state, ip } = await describeInstance(aws, env.AWS_REGION, env.AWS_INSTANCE_ID);
        return new Response(JSON.stringify({ state, ip }), {
          headers: { "content-type": "application/json" },
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: "AWS API request failed", detail: String(err) }), {
          status: 502,
          headers: { "content-type": "application/json" },
        });
      }
    }

    try {
      let { state, ip } = await describeInstance(aws, env.AWS_REGION, env.AWS_INSTANCE_ID);

      if (state === "terminated" || state === "shutting-down") {
        return new Response(JSON.stringify({ error: "instance is terminated", state }), {
          status: 409,
          headers: { "content-type": "application/json" },
        });
      }

      if (state === "stopped") {
        await ec2Request(aws, env.AWS_REGION, "StartInstances", env.AWS_INSTANCE_ID);
        state = "pending";
      }

      const deadline = Date.now() + POLL_TIMEOUT_MS;
      while (state !== "running" && Date.now() < deadline) {
        await sleep(POLL_INTERVAL_MS);
        ({ state, ip } = await describeInstance(aws, env.AWS_REGION, env.AWS_INSTANCE_ID));
      }

      if (state !== "running" || !ip) {
        return new Response(JSON.stringify({ error: "instance did not become reachable in time", state }), {
          status: 504,
          headers: { "content-type": "application/json" },
        });
      }

      return new Response(JSON.stringify({ ip }), {
        headers: { "content-type": "application/json" },
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: "AWS API request failed", detail: String(err) }), {
        status: 502,
        headers: { "content-type": "application/json" },
      });
    }
  },
};
