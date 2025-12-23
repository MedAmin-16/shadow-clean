const BLACKLISTED_DOMAINS = [
  '.gov', '.gov.uk', '.gov.au', '.gov.ca', '.gov.in',
  '.mil', '.military',
  'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com',
  'jpmorgan.com', 'goldmansachs.com', 'morganstanley.com', 'barclays.com',
  'hsbc.com', 'ubs.com', 'creditsuisse.com', 'deutschebank.com',
  'visa.com', 'mastercard.com', 'americanexpress.com', 'paypal.com',
  '.edu',
];

const BLACKLISTED_IP_RANGES = [
  '10.',
  '192.168.',
  '172.16.',
  '172.17.',
  '172.18.',
  '172.19.',
  '172.20.',
  '172.21.',
  '172.22.',
  '172.23.',
  '172.24.',
  '172.25.',
  '172.26.',
  '172.27.',
  '172.28.',
  '172.29.',
  '172.30.',
  '172.31.',
  '127.',
  '169.254.',
];

export interface BlacklistCheckResult {
  blocked: boolean;
  reason?: string;
}

export function isTargetBlacklisted(target: string): BlacklistCheckResult {
  const normalized = target.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];

  for (const domain of BLACKLISTED_DOMAINS) {
    if (normalized.endsWith(domain) || normalized.includes(domain)) {
      return { blocked: true, reason: `Target matches restricted domain pattern: ${domain}` };
    }
  }

  for (const ipRange of BLACKLISTED_IP_RANGES) {
    if (normalized.startsWith(ipRange)) {
      return { blocked: true, reason: `Target is in restricted IP range: ${ipRange}*` };
    }
  }

  return { blocked: false };
}
