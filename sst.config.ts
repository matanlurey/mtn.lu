/// <reference path="./.sst/platform/config.d.ts" />
///
/// TIP: Use "sst install" to install the required dependencies for this file.

export default $config({
  app(input) {
    return {
      name: "mtn-lu",
      removal: input?.stage === "production" ? "retain" : "remove",
      protect: ["production"].includes(input?.stage),
      home: "aws",
    };
  },

  async run() {
    const jwtSecret = new sst.Secret("JwtSecret");
    const dbPassword = new sst.Secret("DbPassword");

    const vpc = new sst.aws.Vpc("MainVpc", { nat: "ec2" });

    const db = new sst.aws.Postgres("MainDb", {
      vpc,
      database: "mtn_lu",
      username: "postgres",
      password: dbPassword.value,
      instance: "t4g.micro",
      version: "16.12",
    });

    const authFn = new sst.aws.Function("AuthFn", {
      url: true,
      streaming: false,
      runtime: "go",
      handler: ".",
      architecture: "arm64",
      vpc,
      link: [db, jwtSecret],
      environment: {
        DATABASE_URL: $interpolate`postgres://postgres:${dbPassword.value}@${db.host}:${db.port}/mtn_lu`,
        INIT_DB: "true",
        JWT_SECRET: jwtSecret.value,
        BASE_URL: "https://mtn.lu",
        SMTP_HOST: "email-smtp.us-east-1.amazonaws.com",
        SMTP_PORT: "587",
        SMTP_FROM: "login@mtn.lu",
      },
    });

    return {
      authUrl: authFn.url,
      dbHost: db.host,
      dbPort: db.port,
    };
  },
});
