/**
 * Risk scoring presentation helpers. The analyzer service returns a calibrated
 * probability in [0, 1]; the UI maps it to a human band + colour. Kept pure so
 * the mapping is unit-tested and shared across the app.
 */

export type RiskBand = 'safe' | 'caution' | 'danger';

export interface RiskPresentation {
  band: RiskBand;
  label: string;
  /** Tailwind text colour token for the band. */
  colorClass: string;
  /** 0–100 integer for display. */
  percent: number;
}

/** Inclusive lower bound (on a 0–1 score) for each band. */
export const RISK_THRESHOLDS = {
  caution: 0.4,
  danger: 0.75,
} as const;

export function riskBand(score: number): RiskBand {
  const s = clamp01(score);
  if (s >= RISK_THRESHOLDS.danger) return 'danger';
  if (s >= RISK_THRESHOLDS.caution) return 'caution';
  return 'safe';
}

const BAND_META: Record<RiskBand, { label: string; colorClass: string }> = {
  safe: { label: 'Looks safe', colorClass: 'text-risk-safe' },
  caution: { label: 'Be cautious', colorClass: 'text-risk-caution' },
  danger: { label: 'Likely phishing', colorClass: 'text-risk-danger' },
};

export function presentRisk(score: number): RiskPresentation {
  const s = clamp01(score);
  const band = riskBand(s);
  return {
    band,
    ...BAND_META[band],
    percent: Math.round(s * 100),
  };
}

function clamp01(n: number): number {
  if (Number.isNaN(n)) return 0;
  return Math.min(1, Math.max(0, n));
}
