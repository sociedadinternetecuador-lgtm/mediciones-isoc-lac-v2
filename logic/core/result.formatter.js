function buildStandardResponse({ domain, indicator, payload }) {
  return {
    domain,
    analyzed_object: {
      type: "domain",
      value: domain
    },
    [indicator]: payload
  };
}

module.exports = { buildStandardResponse };