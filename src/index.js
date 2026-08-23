import { AwsClient } from "aws4fetch";

export default {
  async fetch(request, env) {
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
