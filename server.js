import express from "express";
import cors from "cors";
import { STSClient, AssumeRoleCommand } from "@aws-sdk/client-sts";
import { S3Client, ListBucketsCommand } from "@aws-sdk/client-s3";

const app = express();
app.use(cors());
app.use(express.json());

app.post("/scan", async (req, res) => {
  try {
    const { roleArn, externalId } = req.body;

    // 1. Assume role
    const sts = new STSClient({ region: "us-east-1" });

    const assume = await sts.send(
      new AssumeRoleCommand({
        RoleArn: roleArn,
        RoleSessionName: "nishverse-session",
        ExternalId: externalId || "nishverse-audit",
      })
    );

    const creds = assume.Credentials;

    // 2. Use temp creds to call AWS
    const s3 = new S3Client({
      region: "us-east-1",
      credentials: {
        accessKeyId: creds.AccessKeyId,
        secretAccessKey: creds.SecretAccessKey,
        sessionToken: creds.SessionToken,
      },
    });

    const buckets = await s3.send(new ListBucketsCommand({}));

    // 3. Return simple findings
    res.json({
      success: true,
      findings: [
        {
          id: "s3_check",
          severity: "INFO",
          message: `Found ${buckets.Buckets.length} buckets`,
        },
      ],
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/", (req, res) => {
  res.send("Nishverse backend running");
});

app.listen(3000, () => console.log("Server running on port 3000"));
