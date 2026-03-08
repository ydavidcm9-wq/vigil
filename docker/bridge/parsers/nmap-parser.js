const { XMLParser } = require("fast-xml-parser");

/**
 * Parse nmap XML output (-oX) into structured JSON.
 *
 * Returns: {
 *   scan_info: { scanner, args, start, startstr, version, xmloutputversion },
 *   hosts: [{
 *     address: { addr, addrtype },
 *     hostnames: [{ name, type }],
 *     status: { state, reason },
 *     ports: [{
 *       portid, protocol, state, reason,
 *       service: { name, product, version, extrainfo, ostype, method, conf },
 *       scripts: [{ id, output }]
 *     }],
 *     os: { matches: [{ name, accuracy, family, generation }], fingerprint },
 *     uptime: { seconds, lastboot },
 *     distance: { value },
 *     trace: { hops: [{ ttl, rtt, ipaddr, host }] }
 *   }],
 *   run_stats: { finished: { time, timestr, elapsed, summary, exit }, hosts: { up, down, total } }
 * }
 */
function parseNmapXml(xmlContent) {
  if (!xmlContent || typeof xmlContent !== "string") {
    return { scan_info: {}, hosts: [], run_stats: {} };
  }

  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: "",
    isArray: (name) => {
      return [
        "host",
        "port",
        "hostname",
        "osmatch",
        "osclass",
        "script",
        "hop",
        "address",
        "elem",
        "table",
      ].includes(name);
    },
  });

  let parsed;
  try {
    parsed = parser.parse(xmlContent);
  } catch (err) {
    return { scan_info: {}, hosts: [], run_stats: {}, parse_error: err.message };
  }

  const nmaprun = parsed.nmaprun || parsed;
  if (!nmaprun) {
    return { scan_info: {}, hosts: [], run_stats: {} };
  }

  // ── Scan info ──
  const scanInfo = {
    scanner: nmaprun.scanner || "nmap",
    args: nmaprun.args || "",
    start: nmaprun.start || "",
    startstr: nmaprun.startstr || "",
    version: nmaprun.version || "",
    xmloutputversion: nmaprun.xmloutputversion || "",
  };

  // ── Hosts ──
  const rawHosts = nmaprun.host || [];
  const hostArray = Array.isArray(rawHosts) ? rawHosts : [rawHosts];

  const hosts = hostArray
    .filter((h) => h)
    .map((host) => {
      // Address(es)
      const addresses = normalizeArray(host.address);
      const primaryAddr = addresses[0] || {};

      // Hostnames
      const hostnames = normalizeArray(
        host.hostnames?.hostname || host.hostnames
      ).map((h) => ({
        name: h.name || h,
        type: h.type || "unknown",
      }));

      // Status
      const status = {
        state: host.status?.state || "unknown",
        reason: host.status?.reason || "",
      };

      // Ports
      const rawPorts = normalizeArray(host.ports?.port);
      const ports = rawPorts.map((p) => {
        const service = p.service || {};
        const scripts = normalizeArray(p.script).map((s) => ({
          id: s.id || "",
          output: s.output || "",
        }));

        return {
          portid: parseInt(p.portid) || 0,
          protocol: p.protocol || "tcp",
          state: p.state?.state || "unknown",
          reason: p.state?.reason || "",
          service: {
            name: service.name || "",
            product: service.product || "",
            version: service.version || "",
            extrainfo: service.extrainfo || "",
            ostype: service.ostype || "",
            method: service.method || "",
            conf: parseInt(service.conf) || 0,
          },
          scripts: scripts.length > 0 ? scripts : undefined,
        };
      });

      // OS detection
      const osMatches = normalizeArray(host.os?.osmatch).map((m) => {
        const classes = normalizeArray(m.osclass);
        return {
          name: m.name || "",
          accuracy: parseInt(m.accuracy) || 0,
          family: classes[0]?.osfamily || "",
          generation: classes[0]?.osgen || "",
          vendor: classes[0]?.vendor || "",
          type: classes[0]?.type || "",
        };
      });

      const osFingerprint = host.os?.osfingerprint?.fingerprint || "";

      // Uptime
      const uptime = host.uptime
        ? {
            seconds: parseInt(host.uptime.seconds) || 0,
            lastboot: host.uptime.lastboot || "",
          }
        : undefined;

      // Distance
      const distance = host.distance
        ? { value: parseInt(host.distance.value) || 0 }
        : undefined;

      // Traceroute
      const hops = normalizeArray(host.trace?.hop).map((h) => ({
        ttl: parseInt(h.ttl) || 0,
        rtt: parseFloat(h.rtt) || 0,
        ipaddr: h.ipaddr || "",
        host: h.host || "",
      }));

      return {
        address: {
          addr: primaryAddr.addr || "",
          addrtype: primaryAddr.addrtype || "ipv4",
        },
        all_addresses: addresses.map((a) => ({
          addr: a.addr || "",
          addrtype: a.addrtype || "",
        })),
        hostnames,
        status,
        ports,
        os: {
          matches: osMatches,
          fingerprint: osFingerprint || undefined,
        },
        uptime,
        distance,
        trace: hops.length > 0 ? { hops } : undefined,
      };
    });

  // ── Run stats ──
  const runStats = {
    finished: {
      time: nmaprun.runstats?.finished?.time || "",
      timestr: nmaprun.runstats?.finished?.timestr || "",
      elapsed: parseFloat(nmaprun.runstats?.finished?.elapsed) || 0,
      summary: nmaprun.runstats?.finished?.summary || "",
      exit: nmaprun.runstats?.finished?.exit || "",
    },
    hosts: {
      up: parseInt(nmaprun.runstats?.hosts?.up) || 0,
      down: parseInt(nmaprun.runstats?.hosts?.down) || 0,
      total: parseInt(nmaprun.runstats?.hosts?.total) || 0,
    },
  };

  return {
    scan_info: scanInfo,
    hosts,
    run_stats: runStats,
  };
}

/**
 * Normalize a value to an array.
 */
function normalizeArray(val) {
  if (!val) return [];
  if (Array.isArray(val)) return val;
  return [val];
}

module.exports = { parseNmapXml };
