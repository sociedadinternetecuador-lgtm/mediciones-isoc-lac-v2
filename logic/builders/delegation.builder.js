function buildDelegationsFromZones(zones) {
  const delegations = [];

  for (let i = 0; i < zones.length - 1; i++) {
    delegations.push({
      from: zones[i].zone,
      to: zones[i + 1].zone
    });
  }

  return delegations;
}

module.exports = { buildDelegationsFromZones };