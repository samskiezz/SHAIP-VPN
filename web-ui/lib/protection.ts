/** This browser UI has no authenticated native VPN bridge or OS packet path. */
export function browserProtection(preview: boolean, requested: boolean, nodes: number) {
  return {
    protected: false as const,
    simulatedConnected: preview && requested && nodes > 0,
    canSimulate: preview,
    message: preview
      ? "Design preview — all tunnel indicators are simulated. This page does not protect traffic."
      : "VPN protection unavailable in this browser. Use the native Linux tunnel; this page does not route or block device traffic.",
  };
}
