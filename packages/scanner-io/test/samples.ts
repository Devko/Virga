// Hand-written sample reports. They follow the documented JSON output of
// osv-scanner 2 (`--format json`), Trivy with report `SchemaVersion` 2
// (`--format json`) and gitleaks 8 (`--report-format json`). They are not
// captured from real runs; S-07 replaces them with captured output.

/**
 * Dummy secrets, built at run time so that no token-shaped literal sits in
 * the repository. The body after the prefix must never leave a reader.
 */
export const CF_SECRET_BODY = ["Q7mZ2xVb9K", "pL4wTr8NcY", "6hJd3sFg1a", "Xe5uWo0iRk"].join("");
export const CF_SECRET = `cfat_${CF_SECRET_BODY}`;
export const PLAIN_SECRET = ["Lk2Pq9Wz", "Tb7Vn4Rx", "Ys1Mc8Hd"].join("");
const KEY_BODY = ["MIIEvQIBADAN", "BgkqhkiG9w0B", "Jb3XnqDummy0"].join("");
export const KEY_SECRET = [
  "-----BEGIN PRIVATE KEY-----",
  KEY_BODY,
  "-----END PRIVATE KEY-----",
].join("\n");

/** Every secret body seeded into the samples. */
export const SEEDED_BODIES = [CF_SECRET_BODY, PLAIN_SECRET, KEY_BODY];

const ghsaLodash = {
  modified: "2024-03-01T00:00:00Z",
  published: "2021-02-15T00:00:00Z",
  schema_version: "1.6.0",
  id: "GHSA-35jh-r3h4-6jhm",
  aliases: ["CVE-2021-23337"],
  summary: "Command Injection in lodash",
  details: "lodash versions prior to 4.17.21 are vulnerable to Command Injection.",
  affected: [
    {
      package: { ecosystem: "npm", name: "lodash", purl: "pkg:npm/lodash" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
      database_specific: { source: "https://github.com/github/advisory-database" },
    },
  ],
  severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" }],
  references: [{ type: "ADVISORY", url: "https://nvd.nist.gov/vuln/detail/CVE-2021-23337" }],
  database_specific: {
    cwe_ids: ["CWE-77", "CWE-94"],
    github_reviewed: true,
    severity: "HIGH",
    nvd_published_at: "2021-02-15T13:15:00Z",
  },
};

export const osvSample = {
  results: [
    {
      source: { path: "/scan/package-lock.json", type: "lockfile" },
      packages: [
        {
          package: { name: "lodash", version: "4.17.20", ecosystem: "npm" },
          dependency_groups: [],
          vulnerabilities: [
            ghsaLodash,
            {
              id: "GHSA-29mw-wpgm-hmr9",
              aliases: ["CVE-2020-28500"],
              summary: "Regular Expression Denial of Service (ReDoS) in lodash",
              affected: [
                {
                  package: { ecosystem: "npm", name: "lodash" },
                  ranges: [
                    { type: "SEMVER", events: [{ introduced: "4.0.0" }, { fixed: "4.17.21" }] },
                  ],
                },
              ],
              database_specific: { severity: "MODERATE" },
            },
          ],
          groups: [
            {
              ids: ["GHSA-35jh-r3h4-6jhm"],
              aliases: ["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"],
              max_severity: "7.2",
            },
            {
              ids: ["GHSA-29mw-wpgm-hmr9"],
              aliases: ["CVE-2020-28500", "GHSA-29mw-wpgm-hmr9"],
              max_severity: "5.3",
            },
          ],
        },
        {
          package: { name: "@babel/traverse", version: "7.22.0", ecosystem: "npm" },
          vulnerabilities: [
            {
              id: "GHSA-67hx-6x53-jw92",
              aliases: ["CVE-2023-45133"],
              affected: [
                {
                  package: { ecosystem: "npm", name: "@babel/traverse" },
                  ranges: [
                    { type: "SEMVER", events: [{ introduced: "0" }, { fixed: "7.23.2" }] },
                    {
                      type: "SEMVER",
                      events: [{ introduced: "8.0.0-alpha.0" }, { fixed: "8.0.0-alpha.4" }],
                    },
                  ],
                },
              ],
              database_specific: { severity: "CRITICAL" },
            },
          ],
          groups: [
            {
              ids: ["GHSA-67hx-6x53-jw92"],
              aliases: ["CVE-2023-45133", "GHSA-67hx-6x53-jw92"],
              max_severity: "9.3",
            },
          ],
        },
        {
          package: { name: "requests", version: "2.25.0", ecosystem: "PyPI" },
          vulnerabilities: [
            {
              id: "PYSEC-2023-74",
              aliases: ["CVE-2023-32681", "GHSA-j8r2-6x86-q33q"],
              affected: [
                {
                  package: { ecosystem: "PyPI", name: "requests" },
                  ranges: [
                    { type: "ECOSYSTEM", events: [{ introduced: "2.3.0" }, { fixed: "2.31.0" }] },
                    {
                      type: "GIT",
                      repo: "https://github.com/psf/requests",
                      events: [{ fixed: "74ea7cf" }],
                    },
                  ],
                  versions: ["2.3.0", "2.25.0", "2.30.0"],
                },
              ],
            },
          ],
          groups: [
            {
              ids: ["PYSEC-2023-74", "GHSA-j8r2-6x86-q33q"],
              aliases: ["CVE-2023-32681", "GHSA-j8r2-6x86-q33q", "PYSEC-2023-74"],
              max_severity: "",
            },
          ],
        },
      ],
    },
  ],
};

const MUSL_PURL = "pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64&distro=3.19.1";
const ZLIB_PURL = "pkg:apk/alpine/zlib@1.3-r2?arch=x86_64&distro=3.19.1";
const layer = {
  Digest: "sha256:4abcf20661432fb2d719aaf90656f55c287f8ca915dc1c92ec14ff61e67fbaf8",
  DiffID: "sha256:d4fc045c9e3a848011de66f34b81f052d4f2c15a17bb196d637e526349601820",
};

export const trivySample = {
  SchemaVersion: 2,
  CreatedAt: "2026-10-01T10:00:00.000000000Z",
  ArtifactName: "registry.example.com/app:1.0",
  ArtifactType: "container_image",
  Metadata: {
    OS: { Family: "alpine", Name: "3.19.1" },
    ImageID: "sha256:05455a08881ea9cf0e752bc48e61bbd71a34c029bb13df01e40e3e70e0d007bd",
    DiffIDs: [layer.DiffID],
    RepoTags: ["registry.example.com/app:1.0"],
    ImageConfig: { architecture: "amd64", os: "linux", config: { Env: ["PATH=/usr/bin"] } },
  },
  Results: [
    {
      Target: "registry.example.com/app:1.0 (alpine 3.19.1)",
      Class: "os-pkgs",
      Type: "alpine",
      Packages: [
        {
          ID: "musl@1.2.4-r2",
          Name: "musl",
          Identifier: { PURL: MUSL_PURL, UID: "c7b8a1f0e1d2c3b4" },
          Version: "1.2.4",
          Release: "r2",
          Arch: "x86_64",
          SrcName: "musl",
          SrcVersion: "1.2.4-r2",
          Licenses: ["MIT"],
          DependsOn: [],
          Layer: layer,
        },
        {
          ID: "zlib@1.3-r2",
          Name: "zlib",
          Identifier: { PURL: ZLIB_PURL, UID: "a1b2c3d4e5f60718" },
          Version: "1.3",
          Release: "r2",
          Licenses: ["Zlib"],
          Layer: layer,
        },
      ],
      Vulnerabilities: [
        {
          VulnerabilityID: "CVE-2025-26519",
          PkgID: "musl@1.2.4-r2",
          PkgName: "musl",
          PkgIdentifier: { PURL: MUSL_PURL, UID: "c7b8a1f0e1d2c3b4" },
          InstalledVersion: "1.2.4-r2",
          FixedVersion: "1.2.4-r3",
          Status: "fixed",
          Layer: layer,
          SeveritySource: "nvd",
          PrimaryURL: "https://avd.aquasec.com/nvd/cve-2025-26519",
          DataSource: { ID: "alpine", Name: "Alpine Secdb", URL: "https://secdb.alpinelinux.org/" },
          Title: "musl: iconv out-of-bounds write",
          Description: "musl libc 0.9.13 through 1.2.5 before 1.2.6 has an out-of-bounds write.",
          Severity: "HIGH",
          CweIDs: ["CWE-787"],
          VendorSeverity: { nvd: 3, alpine: 3 },
          CVSS: { nvd: { V3Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", V3Score: 8.1 } },
          References: ["https://www.openwall.com/lists/musl/2025/02/13/1"],
          PublishedDate: "2025-02-14T04:15:09.05Z",
          LastModifiedDate: "2025-02-14T17:15:23.09Z",
        },
      ],
    },
    {
      Target: "usr/src/app/package-lock.json",
      Class: "lang-pkgs",
      Type: "npm",
      Vulnerabilities: [
        {
          VulnerabilityID: "CVE-2021-23337",
          VendorIDs: ["GHSA-35jh-r3h4-6jhm"],
          PkgID: "lodash@4.17.20",
          PkgName: "lodash",
          PkgIdentifier: { PURL: "pkg:npm/lodash@4.17.20" },
          InstalledVersion: "4.17.20",
          FixedVersion: "4.17.21",
          Status: "fixed",
          Severity: "HIGH",
          Title: "nodejs-lodash: command injection via template",
        },
        {
          VulnerabilityID: "CVE-2024-37890",
          PkgName: "ws",
          InstalledVersion: "8.0.0",
          FixedVersion: "8.17.1, 7.5.10",
          Severity: "UNKNOWN",
        },
      ],
    },
    {
      Target: "usr/src/app/.env",
      Class: "secret",
      Secrets: [
        {
          RuleID: "cloudflare-api-token",
          Category: "Cloudflare",
          Severity: "HIGH",
          Title: "Cloudflare API token",
          StartLine: 3,
          EndLine: 3,
          Code: {
            Lines: [
              {
                Number: 3,
                Content: `CF_TOKEN=${CF_SECRET}`,
                IsCause: true,
                Annotation: "",
                Truncated: false,
                Highlighted: `CF_TOKEN=${CF_SECRET}`,
                FirstCause: true,
                LastCause: true,
              },
            ],
          },
          Match: `CF_TOKEN=${CF_SECRET}`,
          Layer: layer,
        },
      ],
    },
  ],
};

const gitleaksFinding = (fields: Record<string, unknown>) => ({
  Description: "Detected a secret",
  StartColumn: 1,
  EndColumn: 60,
  SymlinkFile: "",
  Commit: "",
  Link: "",
  Entropy: 4.8,
  Author: "",
  Email: "",
  Date: "",
  Message: "",
  Tags: [],
  ...fields,
});

export const gitleaksSample = [
  gitleaksFinding({
    RuleID: "cloudflare-api-token",
    StartLine: 12,
    EndLine: 12,
    Match: `token: "${CF_SECRET}"`,
    Secret: CF_SECRET,
    Line: `  const token = "${CF_SECRET}";`,
    File: "worker.js",
    Fingerprint: "worker.js:cloudflare-api-token:12",
  }),
  gitleaksFinding({
    RuleID: "generic-api-key",
    StartLine: 3,
    EndLine: 3,
    Match: `API_KEY = "${PLAIN_SECRET}"`,
    Secret: PLAIN_SECRET,
    File: "src/config.js",
    Fingerprint: "src/config.js:generic-api-key:3",
  }),
  gitleaksFinding({
    RuleID: "private-key",
    StartLine: 20,
    EndLine: 22,
    Match: KEY_SECRET,
    Secret: KEY_SECRET,
    File: "keys/dev.pem",
    Fingerprint: "keys/dev.pem:private-key:20",
  }),
];

export const json = (value: unknown): string => JSON.stringify(value);
