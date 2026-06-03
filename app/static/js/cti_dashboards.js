/**
 * CTI dashboards (MVP placeholders) for TS-CTI-001 v1.0.
 * Indicator Feed is API-backed; remaining panels are lightweight stubs.
 */
document.addEventListener("alpine:init", () => {
  Alpine.data("ctiDashboards", () => ({
    tabs: [
      { key: "indicator_feed", title: "Indicator Feed", ready: true },
      { key: "actor_profiles", title: "Actor Profiles", ready: true },
      { key: "relationship_graph", title: "Relationship Graph", ready: false },
      { key: "threat_geo_map", title: "Threat Geographic Map", ready: false },
      { key: "attack_matrix", title: "MITRE ATT&CK Matrix", ready: true },
      { key: "siem_alerting", title: "SIEM Alerting", ready: true },
    ],
  }));
});
