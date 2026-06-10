import { describe, expect, it } from 'vitest';

import { presentRisk, riskBand } from './risk';

describe('riskBand', () => {
  it('classifies low scores as safe', () => {
    expect(riskBand(0)).toBe('safe');
    expect(riskBand(0.39)).toBe('safe');
  });

  it('classifies mid scores as caution', () => {
    expect(riskBand(0.4)).toBe('caution');
    expect(riskBand(0.74)).toBe('caution');
  });

  it('classifies high scores as danger', () => {
    expect(riskBand(0.75)).toBe('danger');
    expect(riskBand(1)).toBe('danger');
  });

  it('clamps out-of-range and NaN inputs', () => {
    expect(riskBand(-5)).toBe('safe');
    expect(riskBand(42)).toBe('danger');
    expect(riskBand(Number.NaN)).toBe('safe');
  });
});

describe('presentRisk', () => {
  it('produces a label, colour, and integer percent', () => {
    expect(presentRisk(0.91)).toEqual({
      band: 'danger',
      label: 'Likely phishing',
      colorClass: 'text-risk-danger',
      percent: 91,
    });
  });

  it('rounds the percent', () => {
    expect(presentRisk(0.426).percent).toBe(43);
  });
});
