import { beforeEach, describe, expect, it } from "vitest";
import { maskPublicIps, resetMaskedIpMapping } from "./maskPublicIps";

describe("maskPublicIps", () => {
  beforeEach(() => { resetMaskedIpMapping(); });

  it("maps the first public v4 addresses to stable doc placeholders", () => {
    expect(maskPublicIps("hit 8.8.8.8 today")).toBe("hit 198.51.100.1 today");
    expect(maskPublicIps("hit 1.1.1.1 today")).toBe("hit 198.51.100.2 today");
    expect(maskPublicIps("again 8.8.8.8")).toBe("again 198.51.100.1");
  });

  it("leaves every private and special v4 range untouched", () => {
    const kept = [
      "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.254",
      "192.168.0.1", "192.168.1.10", "127.0.0.1", "127.1.2.3",
      "169.254.10.20", "0.0.0.0",
    ];
    for (const ip of kept) expect(maskPublicIps(`addr ${ip} end`), `kept ${ip}`).toBe(`addr ${ip} end`);
  });

  it("masks just outside the private v4 boundaries", () => {
    expect(maskPublicIps("x 172.15.0.1 y")).toBe("x 198.51.100.1 y");
    expect(maskPublicIps("x 172.32.0.1 y")).toBe("x 198.51.100.2 y");
    expect(maskPublicIps("x 9.9.9.9 y")).toBe("x 198.51.100.3 y");
  });

  it("keeps port and CIDR suffixes outside the placeholder", () => {
    expect(maskPublicIps("conn 203.0.113.9:22 ok")).toBe("conn 198.51.100.1:22 ok");
    expect(maskPublicIps("net 8.8.8.0/24 ok")).toBe("net 198.51.100.2/24 ok");
  });

  it("handles adjacent punctuation and many addresses in one line", () => {
    expect(maskPublicIps("(8.8.8.8),[1.1.1.1];\"9.9.9.9\".")).toBe("(198.51.100.1),[198.51.100.2];\"198.51.100.3\".");
  });

  it("leaves invalid octets, versions, timestamps and event ids alone", () => {
    expect(maskPublicIps("bad 999.1.1.1 end")).toBe("bad 999.1.1.1 end");
    expect(maskPublicIps("bad 1.2.3.256 end")).toBe("bad 1.2.3.256 end");
    expect(maskPublicIps("v 1.2.3.4.5 end")).toBe("v 1.2.3.4.5 end");
    expect(maskPublicIps("app 0.1.0 attack v20.0 ocsf 1.9.0")).toBe("app 0.1.0 attack v20.0 ocsf 1.9.0");
    expect(maskPublicIps("at 2026-11-03T13:14:38Z")).toBe("at 2026-11-03T13:14:38Z");
    expect(maskPublicIps("uid 1793452525.215835#event")).toBe("uid 1793452525.215835#event");
    expect(maskPublicIps("id T1059 ok")).toBe("id T1059 ok");
    expect(maskPublicIps("host web-01.example.com user www-data")).toBe("host web-01.example.com user www-data");
  });

  it("maps public v6 to doc placeholders and keeps private v6", () => {
    expect(maskPublicIps("src 2606:4700:4700::1111 dst")).toBe("src 2001:db8::1 dst");
    expect(maskPublicIps("src 2001:4860:4860::8888 dst")).toBe("src 2001:db8::2 dst");
    expect(maskPublicIps("again 2606:4700:4700::1111")).toBe("again 2001:db8::1");
    for (const ip of ["::1", "fe80::1", "fc00::1", "fd12:3456:789a::1"]) {
      expect(maskPublicIps(`addr ${ip} end`), `kept ${ip}`).toBe(`addr ${ip} end`);
    }
  });

  it("keeps v6 timestamps, macs and bracket ports intact", () => {
    expect(maskPublicIps("at 13:14:38 sharp")).toBe("at 13:14:38 sharp");
    expect(maskPublicIps("mac aa:bb:cc:dd:ee:ff end")).toBe("mac aa:bb:cc:dd:ee:ff end");
    expect(maskPublicIps("sock [2606:4700:4700::1111]:443 ok")).toBe("sock [2001:db8::1]:443 ok");
  });

  it("is idempotent on its own output and resets cleanly", () => {
    const once = maskPublicIps("a 8.8.8.8 b 2606:4700:4700::1111 c 10.0.0.1");
    expect(once).toBe("a 198.51.100.1 b 2001:db8::1 c 10.0.0.1");
    expect(maskPublicIps(once)).toBe(once);
    resetMaskedIpMapping();
    expect(maskPublicIps("a 8.8.8.8")).toBe("a 198.51.100.1");
  });

  it("returns empty and ip-free text unchanged", () => {
    expect(maskPublicIps("")).toBe("");
    expect(maskPublicIps("nothing to hide here")).toBe("nothing to hide here");
  });
});
