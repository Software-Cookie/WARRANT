// k6 load test for the L1 path (Build Specification acceptance: p95 < 25 ms at 500 RPS locally).
// Proofs are single-use and bound to their arguments, so requests are pre-signed by load/presign.py.
// Export WARRANT_TOKEN (a warrant chain) and WARRANT_AGENT_KEY_FILE, then:
//   python load/presign.py 23000 > load/requests.json   (immediately before: proofs expire after 60 s)
//   k6 run -e PEP=http://localhost:8080 load/l1-path.js
import http from "k6/http";
import { check } from "k6";
import { SharedArray } from "k6/data";

const requests = new SharedArray("requests", () => JSON.parse(open("./requests.json")));

export const options = {
  scenarios: {
    l1: { executor: "constant-arrival-rate", rate: 500, timeUnit: "1s", duration: "45s", preAllocatedVUs: 200 },
  },
  thresholds: {
    "http_req_duration{expected_response:true}": ["p(95)<25"],
    checks: ["rate>0.999"],
  },
};

export default function () {
  const r = requests[(__VU * 100000 + __ITER) % requests.length];
  const res = http.post(`${__ENV.PEP}/v1/authorize`, r.body, { headers: r.headers });
  check(res, { "decided": (x) => x.status === 200 || x.status === 403 || x.status === 202 });
}
