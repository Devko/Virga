import { describe, expect, it } from "vitest";
import {
  INSTANCE_ID,
  INSTANCE_ID_MAX,
  manualScanInstanceId,
  scanInstanceId,
} from "../src/scan/ids.ts";

const ACCOUNT = "0123456789abcdef0123456789abcdef";
const AT = Date.UTC(2026, 9, 29, 7, 17, 42);

describe("instance IDs", () => {
  it("are deterministic per account and UTC hour", () => {
    expect(scanInstanceId(ACCOUNT, AT)).toBe(`scan-${ACCOUNT}-2026102907`);
    expect(scanInstanceId(ACCOUNT, AT + 40 * 60 * 1000)).toBe(`scan-${ACCOUNT}-2026102907`);
    expect(scanInstanceId(ACCOUNT, AT + 43 * 60 * 1000)).toBe(`scan-${ACCOUNT}-2026102908`);
  });

  it("match the Workflow ID pattern and length limit", () => {
    for (const id of [scanInstanceId(ACCOUNT, AT), manualScanInstanceId(ACCOUNT, AT)]) {
      expect(id).toMatch(INSTANCE_ID);
      expect(id.length).toBeLessThanOrEqual(INSTANCE_ID_MAX);
    }
    expect(manualScanInstanceId(ACCOUNT, AT)).toBe(`scan-${ACCOUNT}-202610290717-manual`);
  });

  it("refuse anything but a 32-character hex account ID", () => {
    for (const bad of ["", "ABCDEF0123456789abcdef0123456789", `${ACCOUNT}0`, "../x", "a:b"]) {
      expect(() => scanInstanceId(bad, AT)).toThrow(TypeError);
    }
  });
});
