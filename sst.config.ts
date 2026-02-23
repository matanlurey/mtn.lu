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
    const jwtSecret = new sst.Secret("JWT_SECRET");
    const smtpUsername = new sst.Secret("SMTP_USER");
    const smtpPassword = new sst.Secret("SMTP_PASS");
    const adminEmail = new sst.Secret("ADMIN_USER");

    const usersTable = new sst.aws.Dynamo("UsersTable", {
      fields: {
        email: "string",
      },
      primaryIndex: { hashKey: "email" },
    });

    const linksTable = new sst.aws.Dynamo("LinksTable", {
      fields: {
        token: "string",
        email: "string",
        createdAt: "string",
      },
      primaryIndex: { hashKey: "token" },
      globalIndexes: {
        "email-index": { hashKey: "email", rangeKey: "createdAt" },
      },
      ttl: "expiresAt",
    });


    const execSync = await import("child_process").then(mod => mod.execSync);
    const revision = execSync("git rev-parse --short HEAD").toString().trim();

    const authFn = new sst.aws.Function("AuthFn", {
      url: true,
      streaming: false,
      runtime: "go",
      handler: ".",
      architecture: "arm64",
      link: [usersTable, linksTable],
      environment: {
        JWT_SECRET: jwtSecret.value,
        BASE_URL: "https://mtn.lu",
        ADMIN_USER: adminEmail.value,
        SMTP_HOST: "email-smtp.us-west-1.amazonaws.com",
        SMTP_PORT: "587",
        SMTP_FROM: "no-reply@mtn.lu",
        SMTP_USER: smtpUsername.value,
        SMTP_PASS: smtpPassword.value,
        USERS_TABLE: usersTable.name,
        LINKS_TABLE: linksTable.name,
        REVISION: revision,
      },
    });

    const router = new sst.aws.Router("MainRouter", {
      domain: {
        name: "mtn.lu",
        dns: sst.aws.dns({
          zone: "Z0125700X20H5J25WPI0",
        }),
      },
      routes: {
        "/*": authFn.url,
      },
    });

    return {
      url: router.url,
    };
  },
});
