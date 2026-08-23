import { AwsClient } from "aws4fetch";

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

export default {
  async fetch(request, env) {
    const token = request.headers.get("X-Auth-Token") ?? "";
    if (!env.AUTH_TOKEN || !timingSafeEqual(token, env.AUTH_TOKEN)) {
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

    const endpoint = `https://ec2.${env.AWS_REGION}.amazonaws.com/?Action=DescribeInstances&InstanceId.1=${env.AWS_INSTANCE_ID}&Version=2016-11-15`;

    const res = await aws.fetch(endpoint);
    if (!res.ok) {
      const body = await res.text();
      return new Response(JSON.stringify({ error: "AWS API request failed", detail: body }), {
        status: 502,
        headers: { "content-type": "application/json" },
      });
    }

    const xml = await res.text();
    const match = xml.match(/<ipAddress>([^<]+)<\/ipAddress>/);
    const ip = match ? match[1] : null;

    if (!ip) {
      return new Response(JSON.stringify({ error: "public IP not found for instance" }), {
        status: 404,
        headers: { "content-type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ ip }), {
      headers: { "content-type": "application/json" },
    });
  },
};
