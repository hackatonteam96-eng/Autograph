/**
 * AuthGraph ITDR — Detection module public API.
 * Import this from Nazrin's dataStore or routes.
 */

const constants = require("./constants");
const eventParser = require("./event_parser");
const sigmaMatcher = require("./sigma_matcher");
const riskEngine = require("./risk_engine");
const correlator = require("./correlator");

module.exports = {
  ...constants,
  ...eventParser,
  ...sigmaMatcher,
  ...riskEngine,
  ...correlator,
};
