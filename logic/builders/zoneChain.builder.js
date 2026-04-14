function buildZoneChain(domain) {
  const parts = domain.split(".");
  const zones = [];

  for (let i = parts.length - 1; i >= 0; i--) {
    zones.push(parts.slice(i).join("."));
  }

  return zones.map((zone, index) => ({
    zone,
    level: index + 1
  }));
}

module.exports = { buildZoneChain };