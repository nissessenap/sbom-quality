// fixture only — never executed by the gate; the deps are what matter.
const isOdd = require("is-odd");
const debug = require("debug")("fixture");
debug("3 is odd? %s", isOdd(3));
